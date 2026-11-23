use std::sync::Arc;

use regex::Regex;

use crate::options::AddressFamily;
use crate::parse::{ObservationRecord, TransportProto, qname_tld};

use super::endpoints::EndpointIndex;

#[derive(Debug, Clone, Default)]
pub struct FilterHeader {
    pub label: String,
    pub qr: QrSelection,
}

impl FilterHeader {
    pub fn is_empty(&self) -> bool {
        self.label.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QrSelection {
    #[default]
    Query,
    Response,
    Both,
}

impl QrSelection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Response => "response",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MatchStats {
    pub matched: u64,
    pub total_observed: u64,
}

#[derive(Debug, Clone)]
pub enum Predicate {
    All(Vec<Predicate>),
    Any(Vec<Predicate>),
    Not(Box<Predicate>),
    True,
    Field(FieldCond),
    Preset(super::presets::PresetKind),
}

#[derive(Debug, Clone)]
pub struct FieldCond {
    pub field: FieldId,
    pub negate: bool,
    pub op: CompareOp,
    pub values: Vec<String>,
    pub regex: Option<Arc<Regex>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldId {
    Qname,
    Qtype,
    Rcode,
    Opcode,
    Qr,
    Aa,
    Tc,
    Rd,
    Ra,
    Ad,
    Cd,
    Malformed,
    Edns,
    NoEdns,
    Do,
    EdnsVersion,
    EdnsOpt,
    Ede,
    NoEde,
    WireLen,
    LatencyMs,
    Initiator,
    Responder,
    Src,
    Dst,
    Family,
    Transport,
    Iface,
    Vlan,
    Preset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Suffix,
    Regex,
    Set,
}

#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    pub endpoints: EndpointIndex,
    pub unknown_tlds: Vec<String>,
}

pub trait FilterPredicate: Send + Sync {
    fn matches(&self, record: &ObservationRecord, arena: &[u8], ctx: &EvalContext) -> bool;
    fn header(&self) -> &FilterHeader;
    fn clone_box(&self) -> Box<dyn FilterPredicate>;
}

impl FilterPredicate for CompiledFilter {
    fn matches(&self, record: &ObservationRecord, arena: &[u8], ctx: &EvalContext) -> bool {
        record_matches_qr(record, self.header.qr)
            && evaluate_predicate(&self.root, record, arena, ctx)
    }

    fn header(&self) -> &FilterHeader {
        &self.header
    }

    fn clone_box(&self) -> Box<dyn FilterPredicate> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct CompiledFilter {
    pub root: Predicate,
    pub header: FilterHeader,
}

impl Default for CompiledFilter {
    fn default() -> Self {
        Self {
            root: Predicate::True,
            header: FilterHeader::default(),
        }
    }
}

pub fn build_compiled(
    root: Predicate,
    label: impl Into<String>,
    qr: QrSelection,
) -> CompiledFilter {
    CompiledFilter {
        root,
        header: FilterHeader {
            label: label.into(),
            qr,
        },
    }
}

pub fn effective_qr(requested: Option<QrSelection>, auto_response: bool) -> QrSelection {
    match requested {
        Some(q) => q,
        None if auto_response => QrSelection::Response,
        None => QrSelection::Query,
    }
}

pub fn record_matches_qr(record: &ObservationRecord, qr: QrSelection) -> bool {
    match qr {
        QrSelection::Both => true,
        QrSelection::Query => !record.qr,
        QrSelection::Response => record.qr,
    }
}

pub fn evaluate_predicate(
    pred: &Predicate,
    record: &ObservationRecord,
    arena: &[u8],
    ctx: &EvalContext,
) -> bool {
    match pred {
        Predicate::True => true,
        Predicate::All(parts) => parts
            .iter()
            .all(|p| evaluate_predicate(p, record, arena, ctx)),
        Predicate::Any(parts) => parts
            .iter()
            .any(|p| evaluate_predicate(p, record, arena, ctx)),
        Predicate::Not(inner) => !evaluate_predicate(inner, record, arena, ctx),
        Predicate::Field(cond) => {
            let ok = eval_field(cond, record, arena, ctx);
            if cond.negate { !ok } else { ok }
        }
        Predicate::Preset(kind) => {
            super::presets::evaluate_preset(*kind, record, arena, &ctx.unknown_tlds)
        }
    }
}

fn eval_field(
    cond: &FieldCond,
    record: &ObservationRecord,
    arena: &[u8],
    ctx: &EvalContext,
) -> bool {
    match cond.field {
        FieldId::Qname => eval_qname(cond, &record.qname),
        FieldId::Qtype => eval_qtype(cond, record.qtype),
        FieldId::Rcode => eval_rcode(cond, record.rcode),
        FieldId::Opcode => eval_string_set(cond, &format!("OP{}", record.opcode)),
        FieldId::Qr => eval_bool(cond, record.qr),
        FieldId::Aa => eval_bool(cond, record.flags.aa),
        FieldId::Tc => eval_bool(cond, record.flags.tc),
        FieldId::Rd => eval_bool(cond, record.flags.rd),
        FieldId::Ra => eval_bool(cond, record.flags.ra),
        FieldId::Ad => eval_bool(cond, record.flags.ad),
        FieldId::Cd => eval_bool(cond, record.flags.cd),
        FieldId::Malformed => eval_bool(cond, record.malformed),
        FieldId::Edns => eval_bool(cond, record.edns.present),
        FieldId::NoEdns => eval_bool(cond, !record.edns.present),
        FieldId::Do => eval_bool(cond, record.edns.dnssec_ok),
        FieldId::EdnsVersion => eval_u64_set(cond, u64::from(record.edns.version)),
        FieldId::EdnsOpt => eval_edns_opt(cond, record),
        FieldId::Ede => eval_ede(cond, record, arena),
        FieldId::NoEde => !record.has_ede(arena),
        FieldId::WireLen => eval_u64_cmp(cond, u64::from(record.wire_len)),
        FieldId::LatencyMs => eval_u64_cmp(cond, u64::from(record.latency_ms)),
        FieldId::Initiator => ctx
            .endpoints
            .ip_matches_any(&cond.values, record.initiator_ip()),
        FieldId::Responder => ctx
            .endpoints
            .ip_matches_any(&cond.values, record.responder_ip()),
        FieldId::Src => ctx
            .endpoints
            .ip_matches_any(&cond.values, &record.src_ip[..record.src_len as usize]),
        FieldId::Dst => ctx
            .endpoints
            .ip_matches_any(&cond.values, &record.dst_ip[..record.dst_len as usize]),
        FieldId::Family => eval_family(cond, record.family),
        FieldId::Transport => eval_transport(cond, record.transport),
        FieldId::Iface => eval_string_set(cond, &record.iface),
        FieldId::Vlan => eval_u64_set(cond, record.vlan.unwrap_or(0).into()),
        FieldId::Preset => true,
    }
}

fn eval_qname(cond: &FieldCond, qname: &str) -> bool {
    let qlower = qname.trim_end_matches('.').to_ascii_lowercase();
    match cond.op {
        CompareOp::Regex => cond.regex.as_ref().is_some_and(|re| re.is_match(&qlower)),
        CompareOp::Suffix => cond.values.iter().any(|v| {
            let s = v.trim_start_matches('.').to_ascii_lowercase();
            qlower == s || qlower.ends_with(&format!(".{s}"))
        }),
        CompareOp::Ne | CompareOp::Eq | CompareOp::Set => {
            let matches = cond.values.iter().any(|v| qlower == v.to_ascii_lowercase());
            match cond.op {
                CompareOp::Ne => !matches,
                _ => matches,
            }
        }
        CompareOp::Gt | CompareOp::Lt => false,
    }
}

fn eval_rcode(cond: &FieldCond, code: u8) -> bool {
    let label = format!("RCODE{code}");
    let matches = cond.values.iter().any(|v| {
        v.eq_ignore_ascii_case(&label)
            || v.parse::<u8>().ok() == Some(code)
            || v.eq_ignore_ascii_case("NXDOMAIN") && code == 3
    });
    match cond.op {
        CompareOp::Ne => !matches,
        _ => matches,
    }
}

fn eval_qtype(cond: &FieldCond, code: u16) -> bool {
    let matches = cond
        .values
        .iter()
        .any(|v| crate::qtype::qtype_token_matches(code, v));
    match cond.op {
        CompareOp::Ne => !matches,
        _ => matches,
    }
}

fn eval_string_set(cond: &FieldCond, value: &str) -> bool {
    let matches = cond.values.iter().any(|v| v.eq_ignore_ascii_case(value));
    match cond.op {
        CompareOp::Ne => !matches,
        _ => matches,
    }
}

fn eval_bool(cond: &FieldCond, value: bool) -> bool {
    let want = cond.values.is_empty() || cond.values.iter().any(|v| v == "1" || v == "true");
    let matches = value == want;
    match cond.op {
        CompareOp::Ne => !matches,
        _ => matches,
    }
}

fn eval_u64_set(cond: &FieldCond, value: u64) -> bool {
    let matches = cond
        .values
        .iter()
        .any(|v| v.parse::<u64>().ok() == Some(value));
    match cond.op {
        CompareOp::Ne => !matches,
        _ => matches,
    }
}

fn eval_u64_cmp(cond: &FieldCond, value: u64) -> bool {
    let Some(limit) = cond.values.first().and_then(|v| parse_size_token(v)) else {
        return false;
    };
    match cond.op {
        CompareOp::Gt => value > limit,
        CompareOp::Lt => value < limit,
        CompareOp::Eq => value == limit,
        CompareOp::Ne => value != limit,
        _ => false,
    }
}

fn parse_size_token(s: &str) -> Option<u64> {
    if let Some(ms) = s.strip_suffix("ms") {
        return ms.parse().ok();
    }
    s.parse().ok()
}

fn eval_edns_opt(cond: &FieldCond, record: &ObservationRecord) -> bool {
    cond.values.iter().any(|v| {
        if let Ok(code) = v.parse::<u16>() {
            record.edns.has_option(code)
        } else {
            false
        }
    })
}

fn eval_ede(cond: &FieldCond, record: &ObservationRecord, arena: &[u8]) -> bool {
    let codes = record.ede_codes(arena);
    if cond.values.is_empty() {
        return !codes.is_empty();
    }
    cond.values.iter().any(|v| {
        v.parse::<u16>()
            .ok()
            .is_some_and(|want| codes.contains(&want))
    })
}

fn eval_family(cond: &FieldCond, family: AddressFamily) -> bool {
    cond.values
        .iter()
        .any(|v| match v.to_ascii_lowercase().as_str() {
            "v4" | "ipv4" => family == AddressFamily::V4,
            "v6" | "ipv6" => family == AddressFamily::V6,
            _ => false,
        })
}

fn eval_transport(cond: &FieldCond, transport: TransportProto) -> bool {
    cond.values
        .iter()
        .any(|v| match v.to_ascii_lowercase().as_str() {
            "udp" => transport == TransportProto::Udp,
            "tcp" => transport == TransportProto::Tcp,
            _ => false,
        })
}

pub fn predicate_requires_response(root: &Predicate) -> bool {
    match root {
        Predicate::True => false,
        Predicate::All(parts) => parts.iter().any(predicate_requires_response),
        Predicate::Any(parts) => parts.iter().any(predicate_requires_response),
        Predicate::Not(inner) => predicate_requires_response(inner),
        Predicate::Preset(kind) => matches!(
            kind,
            super::presets::PresetKind::EdePresent
                | super::presets::PresetKind::Errors
                | super::presets::PresetKind::NoError
                | super::presets::PresetKind::Truncated
                | super::presets::PresetKind::Rcode(_)
        ),
        Predicate::Field(cond) => matches!(
            cond.field,
            FieldId::Rcode
                | FieldId::Ede
                | FieldId::NoEde
                | FieldId::Aa
                | FieldId::Tc
                | FieldId::Ra
                | FieldId::Ad
                | FieldId::LatencyMs
        ),
    }
}

pub fn is_unknown_tld(qname: &str, known: &[String]) -> bool {
    let Some(tld) = qname_tld(qname) else {
        return false;
    };
    !known.iter().any(|k| k.eq_ignore_ascii_case(&tld))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{DnsFlags, EdnsSummary, QnameHash, TransportProto};

    fn sample_record(qr: bool, qname: &str) -> ObservationRecord {
        ObservationRecord {
            slice_sec: 1,
            iface: "eth0".into(),
            vlan: None,
            family: AddressFamily::V4,
            transport: TransportProto::Udp,
            src_ip: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_len: 4,
            dst_ip: [192, 0, 2, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_len: 4,
            src_port: 53,
            dst_port: 53,
            wire_len: 64,
            malformed: false,
            id: 1,
            qr,
            opcode: 0,
            rcode: 0,
            flags: DnsFlags::default(),
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            qname: qname.into(),
            qname_hash: QnameHash(0),
            qtype: 1,
            qclass: 1,
            edns: EdnsSummary::default(),
            ede_off: 0,
            ede_len: 0,
            latency_ms: 0,
        }
    }

    #[test]
    fn and_or_negation() {
        let pred = Predicate::All(vec![
            Predicate::Field(FieldCond {
                field: FieldId::Qtype,
                negate: false,
                op: CompareOp::Set,
                values: vec!["A".into(), "AAAA".into()],
                regex: None,
            }),
            Predicate::Field(FieldCond {
                field: FieldId::Rcode,
                negate: false,
                op: CompareOp::Set,
                values: vec!["RCODE3".into()],
                regex: None,
            }),
        ]);
        let rec = sample_record(true, "a.b.example.com.");
        let mut rec = rec;
        rec.rcode = 3;
        assert!(evaluate_predicate(
            &pred,
            &rec,
            &[],
            &EvalContext::default()
        ));
        rec.rcode = 0;
        assert!(!evaluate_predicate(
            &pred,
            &rec,
            &[],
            &EvalContext::default()
        ));
        let neg = Predicate::Field(FieldCond {
            field: FieldId::Qtype,
            negate: true,
            op: CompareOp::Set,
            values: vec!["PTR".into()],
            regex: None,
        });
        assert!(evaluate_predicate(&neg, &rec, &[], &EvalContext::default()));
    }

    #[test]
    fn qname_suffix() {
        let pred = Predicate::Field(FieldCond {
            field: FieldId::Qname,
            negate: false,
            op: CompareOp::Suffix,
            values: vec!["example.com".into()],
            regex: None,
        });
        let rec = sample_record(false, "a.b.example.com.");
        assert!(evaluate_predicate(
            &pred,
            &rec,
            &[],
            &EvalContext::default()
        ));
    }
}
