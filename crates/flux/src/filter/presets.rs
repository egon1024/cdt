use crate::parse::ObservationRecord;

use super::engine::{CompareOp, FieldCond, FieldId, Predicate, is_unknown_tld};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetKind {
    UnknownTld,
    AForA,
    Rfc1918Ptr,
    QtypeAny,
    Errors,
    Rcode(u8),
    NoError,
    Truncated,
    NoEdns,
    Do,
    EdePresent,
    Malformed,
}

pub fn preset_by_name(name: &str) -> Option<(PresetKind, Predicate)> {
    let kind = match name {
        "unknown-tld" | "unknown-tlds" => PresetKind::UnknownTld,
        "a-for-a" => PresetKind::AForA,
        "rfc1918-ptr" | "ptr-leak" => PresetKind::Rfc1918Ptr,
        "any" | "qtype-any" => PresetKind::QtypeAny,
        "errors" => PresetKind::Errors,
        "no-error" | "noerror" => PresetKind::NoError,
        "truncated" | "tc" => PresetKind::Truncated,
        "no-edns" | "noedns" => PresetKind::NoEdns,
        "do" => PresetKind::Do,
        "ede" | "ede-present" => PresetKind::EdePresent,
        "malformed" => PresetKind::Malformed,
        other if other.starts_with("rcode") => {
            let code = other.trim_start_matches("rcode").parse().ok()?;
            PresetKind::Rcode(code)
        }
        other if other.starts_with("nxdomain") => PresetKind::Rcode(3),
        other if other.starts_with("servfail") => PresetKind::Rcode(2),
        _ => return None,
    };
    Some((kind, preset_predicate(kind)))
}

pub fn preset_label(kind: PresetKind) -> &'static str {
    match kind {
        PresetKind::UnknownTld => "unknown-tld",
        PresetKind::AForA => "a-for-a",
        PresetKind::Rfc1918Ptr => "rfc1918-ptr",
        PresetKind::QtypeAny => "qtype-any",
        PresetKind::Errors => "errors",
        PresetKind::Rcode(_) => "rcode",
        PresetKind::NoError => "no-error",
        PresetKind::Truncated => "truncated",
        PresetKind::NoEdns => "no-edns",
        PresetKind::Do => "do",
        PresetKind::EdePresent => "ede-present",
        PresetKind::Malformed => "malformed",
    }
}

fn preset_predicate(kind: PresetKind) -> Predicate {
    match kind {
        PresetKind::UnknownTld => Predicate::Preset(PresetKind::UnknownTld),
        PresetKind::AForA => Predicate::Preset(PresetKind::AForA),
        PresetKind::Rfc1918Ptr => Predicate::Preset(PresetKind::Rfc1918Ptr),
        PresetKind::QtypeAny => Predicate::Field(field_set(FieldId::Qtype, &["ANY", "TYPE255"])),
        PresetKind::Errors => Predicate::Any(vec![
            Predicate::Field(field_bool(FieldId::Tc, true)),
            Predicate::Not(Box::new(Predicate::Field(field_set(
                FieldId::Rcode,
                &["RCODE0", "0"],
            )))),
        ]),
        PresetKind::Rcode(c) => {
            Predicate::Field(field_set(FieldId::Rcode, &[&format!("RCODE{c}")]))
        }
        PresetKind::NoError => Predicate::Field(field_set(FieldId::Rcode, &["RCODE0", "0"])),
        PresetKind::Truncated => Predicate::Field(field_bool(FieldId::Tc, true)),
        PresetKind::NoEdns => Predicate::Field(field_bool(FieldId::NoEdns, true)),
        PresetKind::Do => Predicate::Field(field_bool(FieldId::Do, true)),
        PresetKind::EdePresent => Predicate::Field(field_bool(FieldId::Ede, false)),
        PresetKind::Malformed => Predicate::Field(field_bool(FieldId::Malformed, true)),
    }
}

pub fn evaluate_preset(
    kind: PresetKind,
    record: &ObservationRecord,
    _arena: &[u8],
    known_tlds: &[String],
) -> bool {
    match kind {
        PresetKind::UnknownTld => is_unknown_tld(&record.qname, known_tlds),
        PresetKind::AForA => {
            record.qtype == 1
                && record
                    .qname
                    .trim_end_matches('.')
                    .split('.')
                    .next()
                    .is_some_and(|label| {
                        label.parse::<std::net::Ipv4Addr>().is_ok() || label.contains(':')
                    })
        }
        PresetKind::Rfc1918Ptr => {
            record.qtype == 12
                && (record.qname.starts_with("10.")
                    || record.qname.starts_with("192.168.")
                    || record.qname.contains(".172."))
        }
        _ => false,
    }
}

fn field_set(field: FieldId, values: &[&str]) -> FieldCond {
    FieldCond {
        field,
        negate: false,
        op: CompareOp::Set,
        values: values.iter().map(|s| (*s).to_string()).collect(),
        regex: None,
    }
}

fn field_bool(field: FieldId, _value: bool) -> FieldCond {
    FieldCond {
        field,
        negate: false,
        op: CompareOp::Eq,
        values: Vec::new(),
        regex: None,
    }
}

pub fn embedded_iana_tlds() -> Vec<String> {
    include_str!("tlds.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::AddressFamily;
    use crate::parse::{DnsFlags, EdnsSummary, QnameHash, TransportProto};

    fn rec(qname: &str, qtype: u16) -> ObservationRecord {
        ObservationRecord {
            slice_sec: 0,
            iface: "t".into(),
            vlan: None,
            family: AddressFamily::V4,
            transport: TransportProto::Udp,
            src_ip: [0; 16],
            src_len: 4,
            dst_ip: [0; 16],
            dst_len: 4,
            src_port: 1,
            dst_port: 53,
            wire_len: 1,
            malformed: false,
            id: 0,
            qr: false,
            opcode: 0,
            rcode: 0,
            flags: DnsFlags::default(),
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            qname: qname.into(),
            qname_hash: QnameHash(0),
            qtype,
            qclass: 1,
            edns: EdnsSummary::default(),
            ede_off: 0,
            ede_len: 0,
            latency_ms: 0,
        }
    }

    #[test]
    fn unknown_tld_detected() {
        let known = vec!["com".into(), "net".into()];
        assert!(evaluate_preset(
            PresetKind::UnknownTld,
            &rec("foo.invalidtld.", 1),
            &[],
            &known
        ));
        assert!(!evaluate_preset(
            PresetKind::UnknownTld,
            &rec("foo.com.", 1),
            &[],
            &known
        ));
        assert_eq!(crate::parse::qname_tld("foo.com."), Some("com".into()));
    }
}
