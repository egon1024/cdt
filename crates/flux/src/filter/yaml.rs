use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use super::engine::{CompareOp, FieldCond, FieldId, Predicate};
use super::flags::FilterParseError;

#[derive(Debug, thiserror::Error)]
pub enum SavedFilterError {
    #[error("{file}:{line}: {message}")]
    FileLine {
        file: String,
        line: u32,
        message: String,
    },

    #[error("unknown field {0}")]
    UnknownField(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum YamlNode {
    Group(YamlGroup),
    Leaf(BTreeMap<String, serde_yaml::Value>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlGroup {
    #[serde(default)]
    all: Vec<YamlNode>,
    #[serde(default)]
    any: Vec<YamlNode>,
    #[serde(default)]
    not: Option<Box<YamlNode>>,
}

pub fn validate_filter_yaml(content: &str, file: &str) -> Result<Predicate, SavedFilterError> {
    parse_yaml_filter(content).map_err(|e| match e {
        SavedFilterError::UnknownField(f) => SavedFilterError::FileLine {
            file: file.into(),
            line: line_for_yaml_field_key(content, &f),
            message: format!("unknown field {f}"),
        },
        other => other,
    })
}

/// Best-effort source line for a YAML filter field key (1-based).
fn line_for_yaml_field_key(content: &str, key: &str) -> u32 {
    let marker = format!("{key}:");
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with(&marker) {
            return (i + 1) as u32;
        }
        if let Some(rest) = trimmed.strip_prefix("- ") {
            if rest.starts_with(&marker) {
                return (i + 1) as u32;
            }
        }
    }
    1
}

pub fn compile_saved_filter(content: &str) -> Result<Predicate, SavedFilterError> {
    parse_yaml_filter(content)
}

fn parse_yaml_filter(content: &str) -> Result<Predicate, SavedFilterError> {
    let root: YamlNode = serde_yaml::from_str(content)?;
    node_to_predicate(&root)
}

fn node_to_predicate(node: &YamlNode) -> Result<Predicate, SavedFilterError> {
    match node {
        YamlNode::Group(g) => {
            if !g.all.is_empty() {
                let parts: Result<Vec<_>, _> = g.all.iter().map(node_to_predicate).collect();
                return Ok(Predicate::All(parts?));
            }
            if !g.any.is_empty() {
                let parts: Result<Vec<_>, _> = g.any.iter().map(node_to_predicate).collect();
                return Ok(Predicate::Any(parts?));
            }
            if let Some(not) = &g.not {
                return Ok(Predicate::Not(Box::new(node_to_predicate(not)?)));
            }
            Ok(Predicate::True)
        }
        YamlNode::Leaf(map) => {
            let mut fields = Vec::new();
            for (key, value) in map {
                fields.push(field_from_yaml(key, value)?);
            }
            if fields.len() == 1 {
                Ok(fields.into_iter().next().unwrap())
            } else {
                Ok(Predicate::All(fields))
            }
        }
    }
}

fn field_from_yaml(key: &str, value: &serde_yaml::Value) -> Result<Predicate, SavedFilterError> {
    let field = map_yaml_field(key)?;
    let values = yaml_values(value);
    Ok(Predicate::Field(FieldCond {
        field,
        negate: false,
        op: CompareOp::Set,
        values,
        regex: None,
    }))
}

fn map_yaml_field(key: &str) -> Result<FieldId, SavedFilterError> {
    match key {
        "qname" => Ok(FieldId::Qname),
        "qtype" => Ok(FieldId::Qtype),
        "rcode" => Ok(FieldId::Rcode),
        "malformed" => Ok(FieldId::Malformed),
        "edns" => Ok(FieldId::Edns),
        "ede" => Ok(FieldId::Ede),
        "initiator" => Ok(FieldId::Initiator),
        "responder" => Ok(FieldId::Responder),
        "src" => Ok(FieldId::Src),
        "dst" => Ok(FieldId::Dst),
        other => Err(SavedFilterError::UnknownField(other.into())),
    }
}

fn yaml_values(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Number(n) => vec![n.to_string()],
        serde_yaml::Value::Bool(b) => vec![b.to_string()],
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

pub fn load_named_filter(
    name: &str,
    search_dirs: &[impl AsRef<Path>],
) -> Result<(String, String), SavedFilterError> {
    for dir in search_dirs {
        let path = dir.as_ref().join(format!("{name}.yaml"));
        if path.is_file() {
            let content = std::fs::read_to_string(&path)?;
            return Ok((path.display().to_string(), content));
        }
    }
    Err(SavedFilterError::FileLine {
        file: name.into(),
        line: 0,
        message: "saved filter not found".into(),
    })
}

impl From<SavedFilterError> for FilterParseError {
    fn from(e: SavedFilterError) -> Self {
        FilterParseError::Invalid(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::EvalContext;
    use crate::filter::engine::evaluate_predicate;
    use crate::options::AddressFamily;
    use crate::parse::{DnsFlags, EdnsSummary, ObservationRecord, QnameHash, TransportProto};

    #[test]
    fn yaml_all_group() {
        let yaml = r#"
all:
  - qtype: 1
  - rcode: 3
"#;
        let pred = compile_saved_filter(yaml).unwrap();
        let rec = ObservationRecord {
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
            qr: true,
            opcode: 0,
            rcode: 3,
            flags: DnsFlags::default(),
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            qname: "x.".into(),
            qname_hash: QnameHash(0),
            qtype: 1,
            qclass: 1,
            edns: EdnsSummary::default(),
            ede_off: 0,
            ede_len: 0,
            latency_ms: 0,
        };
        assert!(evaluate_predicate(
            &pred,
            &rec,
            &[],
            &EvalContext::default()
        ));
    }

    #[test]
    fn unknown_field_errors() {
        let err = compile_saved_filter("answer: foo").unwrap_err();
        assert!(matches!(err, SavedFilterError::UnknownField(_)));
    }

    #[test]
    fn validate_unknown_field_line_in_group() {
        let yaml = "all:\n  - qtype: A\n  - answer_rdata: 192.0.2.1\n";
        let err = validate_filter_yaml(yaml, "bad.yaml").unwrap_err();
        match err {
            SavedFilterError::FileLine { line, message, .. } => {
                assert_eq!(line, 3);
                assert!(message.contains("answer_rdata"));
            }
            other => panic!("{other:?}"),
        }
    }
}
