use std::collections::HashMap;
use std::net::Ipv4Addr;

use dns_core::edns::ede_meaning;

use crate::filter::{CompiledFilter, EvalContext, FilterPredicate, MatchStats, record_matches_qr};
use crate::flow::LatencyKeyStats;
use crate::options::ViewId;
use crate::parse::ede_entries;
use crate::parse::{ObservationRecord, TransportProto, qname_level_label};
use crate::window::TimeSlice;

#[derive(Debug, Default, Clone)]
pub struct ViewCounts {
    pub sources: HashMap<String, u64>,
    pub destinations: HashMap<String, u64>,
    pub qtypes: HashMap<u16, u64>,
    pub rcodes: HashMap<u8, u64>,
    pub opcodes: HashMap<u8, u64>,
    pub qname_levels: HashMap<(u8, String), u64>,
    pub src_x_qname: HashMap<(String, String), u64>,
    pub ede: HashMap<String, u64>,
    pub src_x_ede: HashMap<(String, String), u64>,
    pub interfaces: HashMap<String, u64>,
    pub transports: HashMap<String, u64>,
    pub malformed: u64,
    pub responses_with_ede: u64,
    pub responses_total: u64,
    pub latency_dst: HashMap<String, LatencyKeyStats>,
    pub latency_src: HashMap<String, LatencyKeyStats>,
    pub latency_qtype: HashMap<String, LatencyKeyStats>,
}

impl ViewCounts {
    pub fn merge_add(&mut self, other: &ViewCounts) {
        merge_map(&mut self.sources, &other.sources);
        merge_map(&mut self.destinations, &other.destinations);
        merge_map(&mut self.qtypes, &other.qtypes);
        merge_map(&mut self.rcodes, &other.rcodes);
        merge_map(&mut self.opcodes, &other.opcodes);
        merge_map(&mut self.qname_levels, &other.qname_levels);
        merge_map(&mut self.src_x_qname, &other.src_x_qname);
        merge_map(&mut self.ede, &other.ede);
        merge_map(&mut self.src_x_ede, &other.src_x_ede);
        merge_map(&mut self.interfaces, &other.interfaces);
        merge_map(&mut self.transports, &other.transports);
        self.malformed += other.malformed;
        self.responses_with_ede += other.responses_with_ede;
        self.responses_total += other.responses_total;
        merge_latency_map(&mut self.latency_dst, &other.latency_dst);
        merge_latency_map(&mut self.latency_src, &other.latency_src);
        merge_latency_map(&mut self.latency_qtype, &other.latency_qtype);
    }

    pub fn merge_sub(&mut self, other: &ViewCounts) {
        sub_map(&mut self.sources, &other.sources);
        sub_map(&mut self.destinations, &other.destinations);
        sub_map(&mut self.qtypes, &other.qtypes);
        sub_map(&mut self.rcodes, &other.rcodes);
        sub_map(&mut self.opcodes, &other.opcodes);
        sub_map(&mut self.qname_levels, &other.qname_levels);
        sub_map(&mut self.src_x_qname, &other.src_x_qname);
        sub_map(&mut self.ede, &other.ede);
        sub_map(&mut self.src_x_ede, &other.src_x_ede);
        sub_map(&mut self.interfaces, &other.interfaces);
        sub_map(&mut self.transports, &other.transports);
        self.malformed = self.malformed.saturating_sub(other.malformed);
        self.responses_with_ede = self
            .responses_with_ede
            .saturating_sub(other.responses_with_ede);
        self.responses_total = self.responses_total.saturating_sub(other.responses_total);
        sub_latency_map(&mut self.latency_dst, &other.latency_dst);
        sub_latency_map(&mut self.latency_src, &other.latency_src);
        sub_latency_map(&mut self.latency_qtype, &other.latency_qtype);
    }
}

fn merge_latency_map(
    dst: &mut HashMap<String, LatencyKeyStats>,
    src: &HashMap<String, LatencyKeyStats>,
) {
    for (k, v) in src {
        dst.entry(k.clone()).or_default().merge_add(v);
    }
}

fn sub_latency_map(
    dst: &mut HashMap<String, LatencyKeyStats>,
    src: &HashMap<String, LatencyKeyStats>,
) {
    for (k, v) in src {
        let e = dst.entry(k.clone()).or_default();
        e.merge_sub(v);
        if e.response_count == 0 && e.unanswered == 0 {
            dst.remove(k);
        }
    }
}

fn merge_map<K: std::hash::Hash + Eq + Clone>(dst: &mut HashMap<K, u64>, src: &HashMap<K, u64>) {
    for (k, v) in src {
        *dst.entry(k.clone()).or_insert(0) += v;
    }
}

fn sub_map<K: std::hash::Hash + Eq + Clone>(dst: &mut HashMap<K, u64>, src: &HashMap<K, u64>) {
    for (k, v) in src {
        let e = dst.entry(k.clone()).or_insert(0);
        *e = e.saturating_sub(*v);
        if *e == 0 {
            dst.remove(k);
        }
    }
}

pub fn build_counts(records: &[ObservationRecord], arena: &[u8]) -> ViewCounts {
    build_counts_filtered(
        records,
        arena,
        &CompiledFilter::default(),
        &EvalContext::default(),
    )
    .0
}

pub fn build_counts_from_slice(slice: &TimeSlice) -> ViewCounts {
    build_counts(&slice.records, &slice.arena)
}

pub fn build_counts_filtered(
    records: &[ObservationRecord],
    arena: &[u8],
    filter: &CompiledFilter,
    ctx: &EvalContext,
) -> (ViewCounts, MatchStats) {
    let mut c = ViewCounts::default();
    let mut matched = 0u64;
    let total = records.len() as u64;
    let qr = filter.header.qr;
    for r in records {
        if !record_matches_qr(r, qr) {
            continue;
        }
        if !filter.matches(r, arena, ctx) {
            continue;
        }
        matched += 1;
        accumulate_record(&mut c, r, arena, false);
    }
    (
        c,
        MatchStats {
            matched,
            total_observed: total,
        },
    )
}

pub fn build_counts_from_slices<'a>(
    slices: impl Iterator<Item = &'a TimeSlice>,
    filter: &CompiledFilter,
    ctx: &EvalContext,
) -> (ViewCounts, MatchStats) {
    let mut merged = ViewCounts::default();
    let mut stats = MatchStats::default();
    for slice in slices {
        let (partial, part_stats) =
            build_counts_filtered(&slice.records, &slice.arena, filter, ctx);
        merged.merge_add(&partial);
        stats.matched += part_stats.matched;
        stats.total_observed += part_stats.total_observed;
    }
    (merged, stats)
}

fn accumulate_record(
    c: &mut ViewCounts,
    r: &ObservationRecord,
    arena: &[u8],
    split_ede_extra: bool,
) {
    if r.malformed {
        c.malformed += 1;
    }
    let src = format_ip(&r.src_ip[..r.src_len as usize]);
    let dst = format_ip(&r.dst_ip[..r.dst_len as usize]);
    *c.sources.entry(src.clone()).or_insert(0) += 1;
    *c.destinations.entry(dst).or_insert(0) += 1;
    *c.qtypes.entry(r.qtype).or_insert(0) += 1;
    *c.rcodes.entry(r.rcode).or_insert(0) += 1;
    *c.opcodes.entry(r.opcode).or_insert(0) += 1;
    *c.interfaces.entry(r.iface.clone()).or_insert(0) += 1;
    let transport = match r.transport {
        TransportProto::Udp => "udp",
        TransportProto::Tcp => "tcp",
    };
    *c.transports.entry(transport.into()).or_insert(0) += 1;
    for level in 1..=3 {
        let label = qname_level_label(&r.qname, level);
        if !label.is_empty() {
            *c.qname_levels.entry((level, label.clone())).or_insert(0) += 1;
            let src_label = src.clone();
            *c.src_x_qname.entry((src_label, label)).or_insert(0) += 1;
        }
    }
    if r.unanswered {
        let dst = format_ip(r.responder_ip());
        let src = format_ip(r.initiator_ip());
        c.latency_dst.entry(dst.clone()).or_default().unanswered += 1;
        c.latency_src.entry(src).or_default().unanswered += 1;
        let qt = crate::qtype::qtype_label(r.qtype);
        c.latency_qtype.entry(qt).or_default().unanswered += 1;
    }
    if r.qr && r.paired && r.latency_ms > 0 {
        let dst = format_ip(r.responder_ip());
        let src = format_ip(r.initiator_ip());
        let qt = crate::qtype::qtype_label(r.qtype);
        let e = c.latency_dst.entry(dst).or_default();
        e.hist.record(r.latency_ms);
        e.response_count += 1;
        let e = c.latency_src.entry(src).or_default();
        e.hist.record(r.latency_ms);
        e.response_count += 1;
        let e = c.latency_qtype.entry(qt).or_default();
        e.hist.record(r.latency_ms);
        e.response_count += 1;
    }
    if r.qr {
        c.responses_total += 1;
        let blob = r.ede_blob(arena);
        if !blob.is_empty() {
            c.responses_with_ede += 1;
            let mut seen_codes = std::collections::HashSet::new();
            for (code, extra) in ede_entries(blob) {
                if !seen_codes.insert(code) {
                    continue;
                }
                let key = if split_ede_extra && !extra.is_empty() {
                    format!("{code} {extra}")
                } else {
                    format!("{code} {}", ede_meaning(code))
                };
                *c.ede.entry(key).or_insert(0) += 1;
                *c.src_x_ede
                    .entry((src.clone(), format!("EDE {code}")))
                    .or_insert(0) += 1;
            }
        }
    }
}

pub fn counts_for_view(
    counts: &ViewCounts,
    view: ViewId,
    key_cap: usize,
    show_no_ede: bool,
) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = match view {
        ViewId::Sources => counts
            .sources
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
        ViewId::Destinations => counts
            .destinations
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
        ViewId::Qtype => counts
            .qtypes
            .iter()
            .map(|(k, v)| (crate::qtype::qtype_label(*k), *v))
            .collect(),
        ViewId::Rcode => counts
            .rcodes
            .iter()
            .map(|(k, v)| (crate::rcode::rcode_label(*k), *v))
            .collect(),
        ViewId::Opcode => counts
            .opcodes
            .iter()
            .map(|(k, v)| (crate::opcode::opcode_label(*k), *v))
            .collect(),
        ViewId::QnameLevel(level) => counts
            .qname_levels
            .iter()
            .filter(|((l, _), _)| *l == level)
            .map(|((_, name), v)| (name.clone(), *v))
            .collect(),
        ViewId::SrcXQname(level) => counts
            .src_x_qname
            .iter()
            .filter_map(|((src, name), v)| {
                let lbl = qname_level_label(name, level);
                if lbl.is_empty() {
                    None
                } else {
                    Some((format!("{src} × {lbl}"), *v))
                }
            })
            .collect(),
        ViewId::Ede => {
            let mut rows: Vec<_> = counts.ede.iter().map(|(k, v)| (k.clone(), *v)).collect();
            if show_no_ede && counts.responses_total > counts.responses_with_ede {
                rows.push((
                    "no EDE".into(),
                    counts.responses_total - counts.responses_with_ede,
                ));
            }
            rows
        }
        ViewId::SrcXEde => counts
            .src_x_ede
            .iter()
            .map(|(k, v)| (format!("{} × {}", k.0, k.1), *v))
            .collect(),
        ViewId::Interface => counts
            .interfaces
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
        ViewId::Transport => counts
            .transports
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
        ViewId::LatencyDst | ViewId::LatencySrc | ViewId::LatencyQtype => Vec::new(),
    };
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    apply_key_cap(&mut rows, key_cap);
    rows
}

fn apply_key_cap(rows: &mut Vec<(String, u64)>, key_cap: usize) {
    if key_cap == 0 || rows.len() <= key_cap {
        return;
    }
    let other: u64 = rows.iter().skip(key_cap).map(|(_, c)| c).sum();
    rows.truncate(key_cap);
    rows.push(("other (cap reached)".into(), other));
}

fn format_ip(ip: &[u8]) -> String {
    match ip.len() {
        4 => Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
        16 => {
            let chunks: Vec<_> = ip
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            if chunks.len() == 8 {
                std::net::Ipv6Addr::from(<[u16; 8]>::try_from(chunks.as_slice()).unwrap())
                    .to_string()
            } else {
                hex::const_encode(ip)
            }
        }
        _ => hex::const_encode(ip),
    }
}

mod hex {
    pub fn const_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
