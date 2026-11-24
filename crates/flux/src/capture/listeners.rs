use std::collections::HashMap;

use thiserror::Error;

use super::iface_spec::{IfaceSpecError, ListenerSpec, parse_interface_args};

#[derive(Debug, Clone)]
pub struct NetInterface {
    pub name: String,
    pub up: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ListenerError {
    #[error("unknown interface: {0}")]
    Unknown(String),

    #[error("interface is down: {0}")]
    Down(String),

    #[error("{0}")]
    Spec(#[from] IfaceSpecError),
}

/// Mockable table of host interfaces.
#[derive(Debug, Clone, Default)]
pub struct InterfaceTable {
    entries: HashMap<String, NetInterface>,
}

impl InterfaceTable {
    pub fn from_interfaces(list: impl IntoIterator<Item = NetInterface>) -> Self {
        let mut entries = HashMap::new();
        for iface in list {
            entries.insert(iface.name.clone(), iface);
        }
        Self { entries }
    }

    pub fn lookup(&self, name: &str) -> Option<&NetInterface> {
        self.entries.get(name)
    }

    pub fn all_up_sorted(&self) -> Vec<String> {
        let mut names: Vec<_> = self
            .entries
            .values()
            .filter(|i| i.up)
            .map(|i| i.name.clone())
            .collect();
        names.sort_unstable();
        names
    }
}

#[cfg(target_os = "linux")]
pub fn host_interface_table() -> InterfaceTable {
    let mut entries = HashMap::new();
    if let Ok(read_dir) = std::fs::read_dir("/sys/class/net") {
        for ent in read_dir.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            let oper = std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
                .unwrap_or_default();
            let up = oper.trim() == "up" || oper.trim() == "unknown";
            entries.insert(name.clone(), NetInterface { name, up });
        }
    }
    InterfaceTable { entries }
}

#[cfg(not(target_os = "linux"))]
pub fn host_interface_table() -> InterfaceTable {
    InterfaceTable::default()
}

fn glob_match(glob: &str, name: &str) -> bool {
    if glob == "*" {
        return true;
    }
    if let Some(prefix) = glob.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    glob == name
}

fn excluded(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|g| glob_match(g, name))
}

pub fn resolve_listeners(
    requested: &[String],
    exclude: &[String],
    table: &InterfaceTable,
) -> Result<Vec<ListenerSpec>, ListenerError> {
    let mut specs: Vec<ListenerSpec> = if requested.is_empty() {
        table
            .all_up_sorted()
            .into_iter()
            .filter(|n| !excluded(n, exclude))
            .map(|iface| ListenerSpec {
                iface,
                capture_threads: 1,
            })
            .collect()
    } else {
        let parsed = parse_interface_args(requested)?;
        let mut out = Vec::new();
        for spec in parsed {
            if excluded(&spec.iface, exclude) {
                continue;
            }
            let Some(iface) = table.lookup(&spec.iface) else {
                return Err(ListenerError::Unknown(spec.iface.clone()));
            };
            if !iface.up {
                return Err(ListenerError::Down(spec.iface.clone()));
            }
            out.push(spec);
        }
        out
    };

    specs.sort_by(|a, b| a.iface.cmp(&b.iface));
    Ok(specs)
}

pub fn opened_interfaces_message(specs: &[ListenerSpec]) -> String {
    if specs.is_empty() {
        return "flux: no capture interfaces selected".into();
    }
    let parts: Vec<_> = specs
        .iter()
        .map(|s| {
            if s.capture_threads > 1 {
                format!("{} ({} capture threads)", s.iface, s.capture_threads)
            } else {
                s.iface.clone()
            }
        })
        .collect();
    format!("flux: opened interfaces: {}", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_table() -> InterfaceTable {
        InterfaceTable::from_interfaces([
            NetInterface {
                name: "lo".into(),
                up: true,
            },
            NetInterface {
                name: "eth0".into(),
                up: true,
            },
            NetInterface {
                name: "eth1".into(),
                up: false,
            },
            NetInterface {
                name: "veth0".into(),
                up: true,
            },
        ])
    }

    #[test]
    fn default_all_up_minus_exclude() {
        let table = sample_table();
        let sel = resolve_listeners(&[], &["veth*".into()], &table).unwrap();
        let names: Vec<_> = sel.iter().map(|s| s.iface.as_str()).collect();
        assert_eq!(names, vec!["eth0", "lo"]);
    }

    #[test]
    fn unknown_iface_errors() {
        let table = sample_table();
        let err = resolve_listeners(&["nope".into()], &[], &table).unwrap_err();
        assert_eq!(err, ListenerError::Unknown("nope".into()));
    }

    #[test]
    fn down_iface_errors() {
        let table = sample_table();
        let err = resolve_listeners(&["eth1".into()], &[], &table).unwrap_err();
        assert_eq!(err, ListenerError::Down("eth1".into()));
    }

    #[test]
    fn named_two_interfaces() {
        let table = sample_table();
        let sel = resolve_listeners(&["eth0".into(), "lo".into()], &[], &table).unwrap();
        assert_eq!(sel.len(), 2);
    }
}
