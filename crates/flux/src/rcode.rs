use dns_core::response::{parse_rcode, rcode_name};

pub fn rcode_label(code: u8) -> String {
    rcode_name(u16::from(code))
}

pub fn rcode_token_matches(code: u8, token: &str) -> bool {
    parse_rcode(token) == Some(u16::from(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_common_rcodes() {
        assert_eq!(rcode_label(0), "NOERROR");
        assert_eq!(rcode_label(3), "NXDOMAIN");
        assert_eq!(rcode_label(2), "SERVFAIL");
    }

    #[test]
    fn filter_tokens_match() {
        assert!(rcode_token_matches(0, "NOERROR"));
        assert!(rcode_token_matches(3, "NXDOMAIN"));
        assert!(rcode_token_matches(3, "RCODE3"));
    }
}
