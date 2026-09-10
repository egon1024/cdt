use std::time::Duration;

use dns_core::parse_record_type;
use dns_resolve::{AddressFamilyRequest, ExpansionPolicy};

pub use crate::trace_options_help::TRACE_OPTIONS_HELP;

/// How the operator selected address family (for stderr notice wording).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FamilySource {
    #[default]
    Default,
    Minus4,
    Minus6,
    PlusFamily(AddressFamilyRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceOptions {
    pub qname: String,
    pub server: Option<String>,
    pub qtype: String,
    pub reverse_lookup: bool,
    pub follow_aliases: bool,
    pub family_request: AddressFamilyRequest,
    pub family_source: FamilySource,
    pub use_tcp: bool,
    pub timeout: Duration,
    pub retries: u8,
    pub dnssec: bool,
    pub request_nsid: bool,
    pub use_cache: bool,
    pub cache_skip_qnames: Vec<String>,
    pub save_session: bool,
    pub events: bool,
    pub debug: bool,
    pub fresh: bool,
    pub expansion: ExpansionPolicy,
    pub expand_all_force: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            qname: String::new(),
            server: None,
            qtype: "A".into(),
            reverse_lookup: false,
            follow_aliases: false,
            family_request: AddressFamilyRequest::Auto,
            family_source: FamilySource::Default,
            use_tcp: false,
            timeout: Duration::from_secs(5),
            retries: 2,
            dnssec: false,
            request_nsid: true,
            use_cache: true,
            cache_skip_qnames: Vec::new(),
            save_session: true,
            events: false,
            debug: false,
            fresh: false,
            expansion: ExpansionPolicy::Last,
            expand_all_force: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("missing query name")]
    MissingQname,

    #[error("unexpected argument: {0}")]
    Unexpected(String),

    #[error("unknown option: {0}")]
    UnknownOption(String),

    #[error("option {option} requires a value")]
    MissingValue { option: String },

    #[error("invalid value for {option}: {value}")]
    InvalidValue { option: String, value: String },

    #[error("cannot use -4 and -6 together")]
    AddressFamily,

    #[error("invalid query type: {0}")]
    QueryType(String),
}

pub fn parse_trace_args(args: &[String]) -> Result<TraceOptions, ParseError> {
    let mut options = TraceOptions::default();
    let mut qname: Option<String> = None;
    let mut saw_v4_flag = false;
    let mut saw_v6_flag = false;

    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-4" => {
                if saw_v6_flag {
                    return Err(ParseError::AddressFamily);
                }
                saw_v4_flag = true;
                options.family_request = AddressFamilyRequest::V4;
                options.family_source = FamilySource::Minus4;
            }
            "-6" => {
                if saw_v4_flag {
                    return Err(ParseError::AddressFamily);
                }
                saw_v6_flag = true;
                options.family_request = AddressFamilyRequest::V6;
                options.family_source = FamilySource::Minus6;
            }
            "-x" => {
                options.reverse_lookup = true;
                options.qtype = "PTR".into();
            }
            "-t" | "-qtype" => {
                options.qtype = next_value(args, &mut index, arg)?;
            }
            _ if arg.starts_with('@') => {
                options.server = Some(arg.trim_start_matches('@').to_string());
            }
            _ if arg.starts_with('+') => {
                apply_query_option(&mut options, arg, &mut saw_v4_flag, &mut saw_v6_flag)?
            }
            _ if arg.starts_with('-') && arg.len() > 1 => {
                let type_name = &arg[1..];
                parse_record_type(type_name)
                    .map_err(|_| ParseError::QueryType(type_name.into()))?;
                options.qtype = type_name.to_string();
            }
            _ => {
                if qname.is_some() {
                    return Err(ParseError::Unexpected(arg.clone()));
                }
                qname = Some(arg.clone());
            }
        }
        index += 1;
    }

    let Some(qname) = qname else {
        return Err(ParseError::MissingQname);
    };

    if saw_v4_flag && saw_v6_flag {
        return Err(ParseError::AddressFamily);
    }

    if options.reverse_lookup {
        options.qtype = "PTR".into();
    }

    options.qname = qname;
    Ok(options)
}

fn next_value(args: &[String], index: &mut usize, option: &str) -> Result<String, ParseError> {
    let value_index = index.saturating_add(1);
    let value = args
        .get(value_index)
        .cloned()
        .ok_or_else(|| ParseError::MissingValue {
            option: option.to_string(),
        })?;
    *index = value_index;
    Ok(value)
}

fn apply_query_option(
    options: &mut TraceOptions,
    arg: &str,
    saw_v4_flag: &mut bool,
    saw_v6_flag: &mut bool,
) -> Result<(), ParseError> {
    let body = arg.trim_start_matches('+');
    let (keyword, value, negate) = split_query_option(body);

    match keyword {
        "tcp" => options.use_tcp = !negate,
        "time" | "timeout" => {
            let Some(raw) = value else {
                return Err(ParseError::MissingValue {
                    option: format!("+{keyword}"),
                });
            };
            options.timeout = Duration::from_secs(parse_timeout_seconds(keyword, raw)?);
        }
        "tries" => {
            let Some(raw) = value else {
                return Err(ParseError::MissingValue {
                    option: "+tries".into(),
                });
            };
            options.retries = parse_tries(raw)?;
        }
        "dnssec" => options.dnssec = !negate,
        "nsid" => options.request_nsid = !negate,
        "nonsid" => options.request_nsid = false,
        "events" => options.events = !negate,
        "debug" => options.debug = !negate,
        "cache" => {
            if negate {
                if let Some(raw) = value {
                    options.cache_skip_qnames.push(raw.to_string());
                } else {
                    options.use_cache = false;
                }
            } else {
                options.use_cache = true;
            }
        }
        "save" => options.save_session = !negate,
        "fresh" => options.fresh = !negate,
        "follow" => options.follow_aliases = !negate,
        "family" => {
            let Some(raw) = value else {
                return Err(ParseError::MissingValue {
                    option: "+family".into(),
                });
            };
            let family = parse_family_value(raw)?;
            if matches!(family, AddressFamilyRequest::V4) && *saw_v6_flag {
                return Err(ParseError::AddressFamily);
            }
            if matches!(family, AddressFamilyRequest::V6) && *saw_v4_flag {
                return Err(ParseError::AddressFamily);
            }
            options.family_request = family;
            options.family_source = FamilySource::PlusFamily(family);
        }
        "expand" => {
            let Some(raw) = value else {
                return Err(ParseError::MissingValue {
                    option: "+expand".into(),
                });
            };
            let (policy, force) = parse_expand_value(raw)?;
            options.expansion = policy;
            if force {
                options.expand_all_force = true;
            }
        }
        other => return Err(ParseError::UnknownOption(format!("+{other}"))),
    }

    Ok(())
}

fn split_query_option(body: &str) -> (&str, Option<&str>, bool) {
    if let Some(rest) = body.strip_prefix("no") {
        if let Some((keyword, value)) = rest.split_once('=') {
            return (keyword, Some(value), true);
        }
        return (rest, None, true);
    }

    if let Some((keyword, value)) = body.split_once('=') {
        return (keyword, Some(value), false);
    }

    (body, None, false)
}

fn parse_timeout_seconds(option: &str, raw: &str) -> Result<u64, ParseError> {
    let parsed: u64 = raw.parse().map_err(|_| ParseError::InvalidValue {
        option: format!("+{option}"),
        value: raw.into(),
    })?;
    Ok(parsed.max(1))
}

fn parse_tries(raw: &str) -> Result<u8, ParseError> {
    let parsed: u16 = raw.parse().map_err(|_| ParseError::InvalidValue {
        option: "+tries".into(),
        value: raw.into(),
    })?;
    Ok((parsed.max(1)) as u8)
}

fn parse_family_value(raw: &str) -> Result<AddressFamilyRequest, ParseError> {
    match raw {
        "auto" => Ok(AddressFamilyRequest::Auto),
        "v4" => Ok(AddressFamilyRequest::V4),
        "v6" => Ok(AddressFamilyRequest::V6),
        "both" => Ok(AddressFamilyRequest::Both),
        other => Err(ParseError::InvalidValue {
            option: "+family".into(),
            value: other.into(),
        }),
    }
}

fn parse_expand_value(raw: &str) -> Result<(ExpansionPolicy, bool), ParseError> {
    let (body, force) = if let Some(stem) = raw.strip_suffix("+force") {
        (stem, true)
    } else {
        (raw, false)
    };
    let policy = match body {
        "last" => ExpansionPolicy::Last,
        "all" => ExpansionPolicy::All,
        "none" => ExpansionPolicy::None,
        other => {
            return Err(ParseError::InvalidValue {
                option: "+expand".into(),
                value: other.into(),
            });
        }
    };
    Ok((policy, force))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_options_help_documents_key_flags() {
        assert!(TRACE_OPTIONS_HELP.contains("+follow"));
        assert!(TRACE_OPTIONS_HELP.contains("+debug"));
        assert!(TRACE_OPTIONS_HELP.contains("+events"));
        assert!(TRACE_OPTIONS_HELP.contains("+timeout=N"));
        assert!(TRACE_OPTIONS_HELP.contains("-x"));
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parses_qname_and_dig_style_options() {
        let options = parse_trace_args(&args(&[
            "example.com",
            "@1.1.1.1",
            "+tcp",
            "+timeout=3",
            "-t",
            "MX",
        ]))
        .expect("parse");

        assert_eq!(options.qname, "example.com");
        assert_eq!(options.server.as_deref(), Some("1.1.1.1"));
        assert!(options.use_tcp);
        assert_eq!(options.timeout, Duration::from_secs(3));
        assert_eq!(options.qtype, "MX");
    }

    #[test]
    fn accepts_time_alias_for_timeout() {
        let options = parse_trace_args(&args(&["example.com", "+time=7"])).expect("parse");
        assert_eq!(options.timeout, Duration::from_secs(7));
    }

    #[test]
    fn clamps_timeout_to_one_second() {
        let options = parse_trace_args(&args(&["example.com", "+timeout=0"])).expect("parse");
        assert_eq!(options.timeout, Duration::from_secs(1));
    }

    #[test]
    fn supports_type_shorthand_and_nonsid() {
        let options =
            parse_trace_args(&args(&["example.com", "-NS", "+nonsid", "+events"])).expect("parse");

        assert_eq!(options.qtype, "NS");
        assert!(!options.request_nsid);
        assert!(options.events);
    }

    #[test]
    fn supports_dnssec_type_shorthand() {
        let options = parse_trace_args(&args(&["example.com", "-TLSA"])).expect("parse");
        assert_eq!(options.qtype, "TLSA");
    }

    #[test]
    fn supports_nocache_for_specific_qname() {
        let options =
            parse_trace_args(&args(&["example.com", "+nocache=ns.example.com"])).expect("parse");

        assert!(options.use_cache);
        assert_eq!(
            options.cache_skip_qnames,
            vec!["ns.example.com".to_string()]
        );
    }

    #[test]
    fn supports_negated_options() {
        let options =
            parse_trace_args(&args(&["example.com", "+notcp", "+nodnssec"])).expect("parse");

        assert!(!options.use_tcp);
        assert!(!options.dnssec);
    }

    #[test]
    fn supports_debug_flag() {
        let options = parse_trace_args(&args(&["example.com", "+debug"])).expect("parse");
        assert!(options.debug);

        let options = parse_trace_args(&args(&["example.com", "+nodebug"])).expect("parse");
        assert!(!options.debug);
    }

    #[test]
    fn supports_fresh_flag() {
        let options = parse_trace_args(&args(&["example.com", "+fresh"])).expect("parse");
        assert!(options.fresh);
    }

    #[test]
    fn supports_reverse_lookup_flag() {
        let options = parse_trace_args(&args(&["192.0.2.1", "-x"])).expect("parse");
        assert!(options.reverse_lookup);
        assert_eq!(options.qtype, "PTR");
        assert_eq!(options.qname, "192.0.2.1");
    }

    #[test]
    fn supports_alias_following_flag() {
        let options =
            parse_trace_args(&args(&["example.com", "+follow", "+nofollow"])).expect("parse");
        assert!(!options.follow_aliases);

        let options = parse_trace_args(&args(&["example.com", "+follow"])).expect("parse");
        assert!(options.follow_aliases);
    }

    #[test]
    fn parses_expand_policy_default() {
        let options = parse_trace_args(&args(&["example.com"])).expect("parse");
        assert_eq!(options.expansion, ExpansionPolicy::Last);
        assert!(!options.expand_all_force);
    }

    #[test]
    fn parses_expand_values() {
        let none = parse_trace_args(&args(&["example.com", "+expand=none"])).expect("parse");
        assert_eq!(none.expansion, ExpansionPolicy::None);

        let all = parse_trace_args(&args(&["example.com", "+expand=all"])).expect("parse");
        assert_eq!(all.expansion, ExpansionPolicy::All);
        assert!(!all.expand_all_force);

        let forced = parse_trace_args(&args(&["example.com", "+expand=all+force"])).expect("parse");
        assert_eq!(forced.expansion, ExpansionPolicy::All);
        assert!(forced.expand_all_force);
    }

    #[test]
    fn rejects_invalid_expand_value() {
        let error =
            parse_trace_args(&args(&["example.com", "+expand=wide"])).expect_err("invalid expand");
        assert!(matches!(error, ParseError::InvalidValue { option, .. } if option == "+expand"));
    }

    #[test]
    fn plain_expand_all_is_not_forced() {
        let options = parse_trace_args(&args(&["example.com", "+expand=all"])).expect("parse");
        assert!(!options.expand_all_force);
    }

    #[test]
    fn default_family_is_auto() {
        let options = parse_trace_args(&args(&["example.com"])).expect("parse");
        assert_eq!(options.family_request, AddressFamilyRequest::Auto);
        assert_eq!(options.family_source, FamilySource::Default);
    }

    #[test]
    fn parses_plus_family_values() {
        let v6 = parse_trace_args(&args(&["example.com", "+family=v6"])).expect("parse");
        assert_eq!(v6.family_request, AddressFamilyRequest::V6);
        assert_eq!(
            v6.family_source,
            FamilySource::PlusFamily(AddressFamilyRequest::V6)
        );

        let both = parse_trace_args(&args(&["example.com", "+family=both"])).expect("parse");
        assert_eq!(both.family_request, AddressFamilyRequest::Both);
    }

    #[test]
    fn rejects_conflicting_family_flags() {
        let error = parse_trace_args(&args(&["example.com", "-4", "-6"])).expect_err("conflict");
        assert!(matches!(error, ParseError::AddressFamily));
    }

    #[test]
    fn rejects_invalid_family_value() {
        let error = parse_trace_args(&args(&["example.com", "+family=dual"])).expect_err("invalid");
        assert!(matches!(
            error,
            ParseError::InvalidValue { option, .. } if option == "+family"
        ));
    }

    #[test]
    fn trace_options_help_documents_family_flags() {
        assert!(TRACE_OPTIONS_HELP.contains("+family=auto|v4|v6|both"));
        assert!(TRACE_OPTIONS_HELP.contains("-4"));
        assert!(TRACE_OPTIONS_HELP.contains("-6"));
    }
}
