use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerSpec {
    pub iface: String,
    pub capture_threads: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IfaceSpecError {
    #[error("invalid interface spec: {0}")]
    Invalid(String),

    #[error("capture thread count must be at least 1")]
    ZeroThreads,
}

pub fn parse_interface_args(raw: &[String]) -> Result<Vec<ListenerSpec>, IfaceSpecError> {
    let mut specs = Vec::new();
    for arg in raw {
        if arg.contains(',') {
            for part in arg.split(',') {
                specs.push(ListenerSpec::parse(part.trim())?);
            }
        } else {
            specs.push(ListenerSpec::parse(arg)?);
        }
    }
    Ok(specs)
}

impl ListenerSpec {
    pub fn parse(raw: &str) -> Result<Self, IfaceSpecError> {
        let (iface, rest) = raw.split_once(':').unwrap_or((raw, ""));
        let mut capture_threads = 1u32;
        if !rest.is_empty() {
            for kv in rest.split(':') {
                let Some((k, v)) = kv.split_once('=') else {
                    return Err(IfaceSpecError::Invalid(raw.into()));
                };
                if k == "threads" {
                    capture_threads = v.parse().map_err(|_| IfaceSpecError::Invalid(raw.into()))?;
                } else {
                    return Err(IfaceSpecError::Invalid(raw.into()));
                }
            }
        }
        if iface.is_empty() {
            return Err(IfaceSpecError::Invalid(raw.into()));
        }
        if capture_threads == 0 {
            return Err(IfaceSpecError::ZeroThreads);
        }
        Ok(Self {
            iface: iface.into(),
            capture_threads,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_threads() {
        let a = ListenerSpec::parse("eth0").unwrap();
        assert_eq!(a.capture_threads, 1);
        let b = ListenerSpec::parse("eth0:threads=4").unwrap();
        assert_eq!(b.capture_threads, 4);
    }

    #[test]
    fn comma_split_args() {
        let v = parse_interface_args(&["eth0,lo".into()]).unwrap();
        assert_eq!(v.len(), 2);
    }
}
