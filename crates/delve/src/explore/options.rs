#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExploreOptions {
    pub plus_icmp: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExploreParseError {
    #[error("unexpected argument: {0}")]
    Unexpected(String),

    #[error("unknown option: {0}")]
    UnknownOption(String),
}

pub fn parse_explore_args(args: &[String]) -> Result<ExploreOptions, ExploreParseError> {
    let mut plus_icmp = false;
    for arg in args {
        match arg.as_str() {
            "+icmp" => plus_icmp = true,
            other if other.starts_with('+') => {
                return Err(ExploreParseError::UnknownOption(other.to_string()));
            }
            other => return Err(ExploreParseError::Unexpected(other.to_string())),
        }
    }
    Ok(ExploreOptions { plus_icmp })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parse_plus_icmp_flag() {
        let options = parse_explore_args(&args(&["+icmp"])).expect("parse");
        assert!(options.plus_icmp);
    }

    #[test]
    fn parse_empty_args() {
        let options = parse_explore_args(&[]).expect("parse");
        assert!(!options.plus_icmp);
    }

    #[test]
    fn rejects_unknown_plus_option() {
        let error = parse_explore_args(&args(&["+fresh"])).expect_err("reject");
        assert!(matches!(error, ExploreParseError::UnknownOption(_)));
    }

    #[test]
    fn rejects_positional_after_id() {
        let error = parse_explore_args(&args(&["01SESSION"])).expect_err("reject");
        assert!(matches!(error, ExploreParseError::Unexpected(_)));
    }
}
