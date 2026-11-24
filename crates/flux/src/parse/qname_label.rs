//! QName grouping labels (naive suffix stack vs public-suffix–aware).

use super::record::qname_level_label;

/// Multi-label public suffixes (longest match wins). Curated subset; extend as needed.
const MULTI_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "co.jp",
    "ne.jp", "or.jp", "co.kr", "com.br", "com.mx", "com.ar", "co.za", "com.cn",
];

fn labels_of(name: &str) -> Vec<String> {
    name.trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

fn suffix_label_len(labels: &[String]) -> usize {
    let mut best = 1usize;
    for rule in MULTI_SUFFIXES {
        let parts: Vec<_> = rule.split('.').collect();
        if labels.len() >= parts.len()
            && labels[labels.len() - parts.len()..]
                .iter()
                .zip(parts.iter())
                .all(|(a, b)| a == b)
        {
            best = best.max(parts.len());
        }
    }
    // single-label TLD is always at least 1
    best.max(1)
}

/// Index in `labels` where registrable domain (eTLD+1) starts.
fn registrable_start(labels: &[String]) -> usize {
    if labels.is_empty() {
        return 0;
    }
    let suf = suffix_label_len(labels);
    if labels.len() <= suf {
        return 0;
    }
    labels.len().saturating_sub(suf + 1)
}

/// Grouping label for qname views at `level` (1–9). Smart mode uses public suffix rules.
pub fn qname_group_label(name: &str, level: u8, smart: bool) -> String {
    if level == 0 || name.is_empty() {
        return name.to_string();
    }
    if !smart {
        return qname_level_label(name, level);
    }
    let labels = labels_of(name);
    if labels.is_empty() {
        return name.to_string();
    }
    let suf_len = suffix_label_len(&labels);
    let reg_idx = registrable_start(&labels);
    let level = level.max(1) as usize;
    let start = match level {
        1 => labels.len().saturating_sub(suf_len),
        2 => reg_idx,
        n => reg_idx.saturating_sub(n - 2),
    };
    labels[start..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn naive_unchanged() {
        assert_eq!(
            qname_group_label("a.b.example.com.", 2, false),
            "example.com"
        );
    }

    #[test]
    fn smart_co_uk_level_2() {
        assert_eq!(
            qname_group_label("www.foo.example.co.uk.", 2, true),
            "example.co.uk"
        );
    }

    #[test]
    fn smart_com_level_2() {
        assert_eq!(
            qname_group_label("www.foo.example.com.", 2, true),
            "example.com"
        );
    }
}