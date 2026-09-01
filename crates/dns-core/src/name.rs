use std::fmt;

use hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};

use crate::error::{DnsCoreError, Result};

/// A DNS domain name in presentation form (trailing dot optional).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainName(String);

impl DomainName {
    pub fn parse(input: &str) -> Result<Self> {
        let normalized = normalize_name(input)?;
        Name::from_ascii(&normalized).map_err(|error| DnsCoreError::Name(error.to_string()))?;
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_wire_name(&self) -> Result<Name> {
        Name::from_ascii(self.as_str()).map_err(|error| DnsCoreError::Name(error.to_string()))
    }

    pub fn zone_cut_for(&self, qname: &DomainName) -> Option<DomainName> {
        let qname_labels = label_count(qname.as_str());
        let zone_labels = label_count(self.as_str());
        if qname_labels <= zone_labels {
            return None;
        }

        let qname = qname.as_str().trim_end_matches('.');
        let zone = self.as_str().trim_end_matches('.');
        if !qname.ends_with(zone) {
            return None;
        }

        let prefix = qname.strip_suffix(zone)?.strip_suffix('.')?;
        let cut = prefix
            .split('.')
            .next_back()
            .map(|label| format!("{label}.{zone}."))
            .or_else(|| Some(format!("{zone}.")))?;

        DomainName::parse(&cut).ok()
    }

    pub fn parent_zone(&self) -> Option<DomainName> {
        let trimmed = self.as_str().trim_end_matches('.');
        let mut labels: Vec<&str> = trimmed.split('.').collect();
        if labels.len() <= 1 {
            return None;
        }
        labels.pop();
        let parent = if labels.is_empty() {
            ".".to_owned()
        } else {
            format!("{}.", labels.join("."))
        };
        DomainName::parse(&parent).ok()
    }

    /// First delegation zone below the DNS root for `qname` (e.g. `org.` for `tuininga.org.`).
    pub fn first_delegation_below_root(&self) -> Option<DomainName> {
        let trimmed = self.as_str().trim_end_matches('.');
        if trimmed.is_empty() {
            return None;
        }
        let labels: Vec<&str> = trimmed.split('.').collect();
        if labels.len() < 2 {
            return None;
        }
        DomainName::parse(&format!("{}.", labels[labels.len() - 1])).ok()
    }

    pub fn is_subdomain_of(&self, parent: &DomainName) -> bool {
        let child = self.as_str().trim_end_matches('.').to_ascii_lowercase();
        let parent = parent.as_str().trim_end_matches('.').to_ascii_lowercase();
        if parent.is_empty() || parent == "." {
            return true;
        }
        child == parent || child.ends_with(&format!(".{parent}"))
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn normalize_name(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(DnsCoreError::Name("empty domain name".into()));
    }

    if trimmed == "." {
        return Ok(".".into());
    }

    let mut normalized = trimmed.trim_end_matches('.').to_string();
    if normalized.is_empty() {
        return Err(DnsCoreError::Name("empty domain name".into()));
    }
    normalized.push('.');
    Ok(normalized)
}

fn label_count(name: &str) -> usize {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() || trimmed == "." {
        return 0;
    }
    trimmed.split('.').count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_trailing_dot() {
        let name = DomainName::parse("example.com").expect("name");
        assert_eq!(name.as_str(), "example.com.");
    }

    #[test]
    fn zone_cut() {
        let zone = DomainName::parse("com.").expect("zone");
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let cut = zone.zone_cut_for(&qname).expect("cut");
        assert_eq!(cut.as_str(), "example.com.");
    }

    #[test]
    fn first_delegation_below_root() {
        let qname = DomainName::parse("tuininga.org.").expect("qname");
        assert_eq!(
            qname.first_delegation_below_root().map(|zone| zone.to_string()),
            Some("org.".into())
        );
        let deep = DomainName::parse("www.example.com.").expect("qname");
        assert_eq!(
            deep.first_delegation_below_root().map(|zone| zone.to_string()),
            Some("com.".into())
        );
    }
}
