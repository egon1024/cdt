use regex::Regex;
use std::sync::Arc;

use super::engine::{CompareOp, FieldCond, FieldId, Predicate};

#[derive(Debug, thiserror::Error)]
pub enum FilterParseError {
    #[error("invalid filter flag: {0}")]
    Invalid(String),

    #[error("invalid regex: {0}")]
    Regex(String),
}

pub fn parse_filter_flags(tokens: &[String]) -> Result<Vec<Predicate>, FilterParseError> {
    let mut preds = Vec::new();
    for tok in tokens {
        let Some(rest) = tok.strip_prefix('+') else {
            continue;
        };
        if rest.starts_with("preset")
            || rest.starts_with("filter")
            || rest.starts_with("qr")
            || rest.starts_with("filter-file")
            || rest.starts_with("tld-list")
            || rest.starts_with("start")
            || rest.starts_with("end")
            || rest.starts_with("key-cap")
            || rest.starts_with("views")
            || rest.starts_with("window")
            || rest.starts_with("defrag")
            || rest.starts_with("tcp")
            || rest.starts_with("pairing")
            || rest.starts_with("pair-timeout")
            || rest.starts_with("pair-max")
            || rest.starts_with("dedup")
        {
            continue;
        }
        if let Some(p) = parse_one_flag(rest)? {
            preds.push(p);
        }
    }
    Ok(preds)
}

fn parse_one_flag(rest: &str) -> Result<Option<Predicate>, FilterParseError> {
    if rest.is_empty() {
        return Ok(None);
    }
    let negated = rest.starts_with("no");
    let body = if negated { &rest[2..] } else { rest };
    let (field_part, op, value_part) = split_field_op_value(body);
    let field = map_field(field_part)?;
    let Some(field) = field else {
        return Ok(None);
    };
    let mut cond = FieldCond {
        field,
        negate: negated,
        op: op.unwrap_or(CompareOp::Set),
        values: Vec::new(),
        regex: None,
    };
    if let Some(values) = value_part {
        cond.values = values
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if cond.field == FieldId::Qname && field_part.ends_with('~') {
        cond.op = CompareOp::Regex;
        let pattern = cond.values.first().cloned().unwrap_or_default();
        cond.regex = Some(Arc::new(
            Regex::new(&pattern).map_err(|e| FilterParseError::Regex(e.to_string()))?,
        ));
    } else if cond.field == FieldId::Qname && cond.op == CompareOp::Set && cond.values.len() == 1 {
        cond.op = CompareOp::Suffix;
    }
    if matches!(cond.field, FieldId::WireLen | FieldId::LatencyMs) {
        cond.op = op.unwrap_or(CompareOp::Gt);
    }
    Ok(Some(Predicate::Field(cond)))
}

fn split_field_op_value(body: &str) -> (&str, Option<CompareOp>, Option<&str>) {
    if let Some((k, v)) = body.split_once("!=") {
        return (k, Some(CompareOp::Ne), Some(v));
    }
    if let Some((k, v)) = body.split_once('>') {
        return (k, Some(CompareOp::Gt), Some(v));
    }
    if let Some((k, v)) = body.split_once('<') {
        return (k, Some(CompareOp::Lt), Some(v));
    }
    if let Some((k, v)) = body.split_once('=') {
        return (k, None, Some(v));
    }
    (body, None, None)
}

fn map_field(name: &str) -> Result<Option<FieldId>, FilterParseError> {
    let id = match name {
        "qname" | "qname~" => FieldId::Qname,
        "qtype" => FieldId::Qtype,
        "rcode" => FieldId::Rcode,
        "opcode" => FieldId::Opcode,
        "qr" => FieldId::Qr,
        "aa" => FieldId::Aa,
        "tc" => FieldId::Tc,
        "rd" => FieldId::Rd,
        "ra" => FieldId::Ra,
        "ad" => FieldId::Ad,
        "cd" => FieldId::Cd,
        "malformed" => FieldId::Malformed,
        "edns" => FieldId::Edns,
        "edns-version" => FieldId::EdnsVersion,
        "do" => FieldId::Do,
        "opt" | "edns-opt" => FieldId::EdnsOpt,
        "ede" => FieldId::Ede,
        "size" | "wire-len" => FieldId::WireLen,
        "latency" => FieldId::LatencyMs,
        "initiator" => FieldId::Initiator,
        "responder" => FieldId::Responder,
        "src" => FieldId::Src,
        "dst" => FieldId::Dst,
        "family" => FieldId::Family,
        "transport" | "udp" | "tcp" => FieldId::Transport,
        "iface" => FieldId::Iface,
        "vlan" => FieldId::Vlan,
        _ => return Ok(None),
    };
    Ok(Some(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comma_or_within_flag() {
        let preds =
            parse_filter_flags(&["+qtype=A,AAAA".into(), "+rcode=NXDOMAIN".into()]).unwrap();
        assert_eq!(preds.len(), 2);
    }

    #[test]
    fn negated_no_prefix() {
        let preds = parse_filter_flags(&["+noedns".into()]).unwrap();
        assert_eq!(preds.len(), 1);
    }

    #[test]
    fn negated_qtype_not_equal() {
        let preds = parse_filter_flags(&["+qtype!=PTR".into()]).unwrap();
        assert_eq!(preds.len(), 1);
    }
}
