use std::time::Duration;

use dns_core::parse_record_type;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceOptions {
    pub qname: String,
    pub server: Option<String>,
    pub qtype: String,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub use_tcp: bool,
    pub timeout: Duration,
    pub retries: u8,
    pub dnssec: bool,
    pub request_nsid: bool,
    pub use_cache: bool,
    pub cache_skip_qnames: Vec<String>,
    pub save_session: bool,
    pub events: bool,
    pub fresh: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            qname: String::new(),
            server: None,
            qtype: "A".into(),
            ipv4_only: false,
            ipv6_only: false,
            use_tcp: false,
            timeout: Duration::from_secs(5),
            retries: 2,
            dnssec: false,
            request_nsid: true,
            use_cache: true,
            cache_skip_qnames: Vec::new(),
            save_session: true,
            events: false,
            fresh: false,
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

    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-4" => options.ipv4_only = true,
            "-6" => options.ipv6_only = true,
            "-t" | "-qtype" => {
                options.qtype = next_value(args, &mut index, arg)?;
            }
            _ if arg.starts_with('@') => {
                options.server = Some(arg.trim_start_matches('@').to_string());
            }
            _ if arg.starts_with('+') => apply_query_option(&mut options, arg)?,
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

    if options.ipv4_only && options.ipv6_only {
        return Err(ParseError::AddressFamily);
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

fn apply_query_option(options: &mut TraceOptions, arg: &str) -> Result<(), ParseError> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn supports_fresh_flag() {
        let options = parse_trace_args(&args(&["example.com", "+fresh"])).expect("parse");
        assert!(options.fresh);
    }
}
