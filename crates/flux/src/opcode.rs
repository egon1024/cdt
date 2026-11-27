use dns_core::response::{opcode_name, parse_opcode};

pub fn opcode_label(code: u8) -> String {
    opcode_name(code)
}

pub fn opcode_token_matches(code: u8, token: &str) -> bool {
    parse_opcode(token) == Some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_common_opcodes() {
        assert_eq!(opcode_label(0), "QUERY");
        assert_eq!(opcode_label(5), "UPDATE");
        assert_eq!(opcode_label(3), "OPCODE3");
    }

    #[test]
    fn filter_tokens_match() {
        assert!(opcode_token_matches(0, "QUERY"));
        assert!(opcode_token_matches(0, "OP0"));
        assert!(opcode_token_matches(4, "NOTIFY"));
    }
}
