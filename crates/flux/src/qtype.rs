use dns_core::query::{parse_record_type, record_type_name};
use hickory_proto::rr::RecordType;

/// Presentation name for a qtype numeric code (SVCB, HTTPS, TYPEnn, …).
pub fn qtype_label(code: u16) -> String {
    record_type_name(RecordType::from(code))
}

/// Whether a filter token (`A`, `HTTPS`, `TYPE64`, `64`, …) matches `code`.
pub fn qtype_token_matches(code: u16, token: &str) -> bool {
    if let Ok(rt) = parse_record_type(token) {
        return u16::from(rt) == code;
    }
    token.parse::<u16>().ok() == Some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_svcb_and_https() {
        assert_eq!(qtype_label(64), "SVCB");
        assert_eq!(qtype_label(65), "HTTPS");
    }

    #[test]
    fn filter_tokens_match_codes() {
        assert!(qtype_token_matches(65, "HTTPS"));
        assert!(qtype_token_matches(64, "SVCB"));
        assert!(qtype_token_matches(64, "TYPE64"));
    }
}
