use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::options::ViewId;
use crate::parse::ObservationRecord;
use crate::parse::qname_level_label;

#[derive(Debug, Default, Clone)]
pub struct ViewCounts {
    pub sources: HashMap<String, u64>,
    pub destinations: HashMap<String, u64>,
    pub qtypes: HashMap<u16, u64>,
    pub rcodes: HashMap<u8, u64>,
    pub opcodes: HashMap<u8, u64>,
    pub qname_levels: HashMap<(u8, String), u64>,
    pub src_x_qname: HashMap<(String, String), u64>,
    pub malformed: u64,
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
        self.malformed += other.malformed;
    }

    pub fn merge_sub(&mut self, other: &ViewCounts) {
        sub_map(&mut self.sources, &other.sources);
        sub_map(&mut self.destinations, &other.destinations);
        sub_map(&mut self.qtypes, &other.qtypes);
        sub_map(&mut self.rcodes, &other.rcodes);
        sub_map(&mut self.opcodes, &other.opcodes);
        sub_map(&mut self.qname_levels, &other.qname_levels);
        sub_map(&mut self.src_x_qname, &other.src_x_qname);
        self.malformed = self.malformed.saturating_sub(other.malformed);
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

pub fn build_counts(records: &[ObservationRecord]) -> ViewCounts {
    let mut c = ViewCounts::default();
    for r in records {
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
        for level in 1..=3 {
            let label = qname_level_label(&r.qname, level);
            if !label.is_empty() {
                *c.qname_levels.entry((level, label.clone())).or_insert(0) += 1;
                let src_label = src.clone();
                *c.src_x_qname.entry((src_label, label)).or_insert(0) += 1;
            }
        }
    }
    c
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

pub fn counts_for_view(counts: &ViewCounts, view: ViewId) -> Vec<(String, u64)> {
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
            .map(|(k, v)| (record_type_name(*k), *v))
            .collect(),
        ViewId::Rcode => counts
            .rcodes
            .iter()
            .map(|(k, v)| (format!("RCODE{}", k), *v))
            .collect(),
        ViewId::Opcode => counts
            .opcodes
            .iter()
            .map(|(k, v)| (format!("OP{}", k), *v))
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
    };
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

fn record_type_name(code: u16) -> String {
    match code {
        1 => "A".into(),
        28 => "AAAA".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        5 => "CNAME".into(),
        _ => format!("TYPE{code}"),
    }
}
