use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Relationships among host network interfaces (bond/bridge/VLAN).
#[derive(Debug, Clone, Default)]
pub struct NetTopology {
    /// iface name → master (bond0, br0, …)
    pub master_of: HashMap<String, String>,
    /// bridge/bond name → member port names
    pub members_of: HashMap<String, HashSet<String>>,
    /// vlan iface name → parent physical iface
    pub vlan_parent: HashMap<String, String>,
}

impl NetTopology {
    pub fn bridge_ports(&self, bridge: &str) -> Option<&HashSet<String>> {
        self.members_of.get(bridge)
    }

    pub fn master(&self, iface: &str) -> Option<&str> {
        self.master_of.get(iface).map(String::as_str)
    }
}

/// Backing store for topology discovery (mockable in tests).
pub trait TopologySource {
    fn read_master_link(&self, iface: &str) -> Option<String>;
    fn read_bridge_members(&self, bridge: &str) -> HashSet<String>;
    fn read_bond_slaves(&self, bond: &str) -> HashSet<String>;
    fn read_vlan_parents(&self) -> HashMap<String, String>;
}

#[derive(Debug, Default)]
pub struct LinuxSysTopology;

impl TopologySource for LinuxSysTopology {
    fn read_master_link(&self, iface: &str) -> Option<String> {
        let path = format!("/sys/class/net/{iface}/master");
        let target = std::fs::read_link(Path::new(&path)).ok()?;
        target.file_name()?.to_str().map(str::to_string)
    }

    fn read_bridge_members(&self, bridge: &str) -> HashSet<String> {
        let dir = PathBuf::from(format!("/sys/class/net/{bridge}/brif"));
        read_dir_names(&dir)
    }

    fn read_bond_slaves(&self, bond: &str) -> HashSet<String> {
        let path = format!("/proc/net/bonding/{bond}");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return HashSet::new();
        };
        let mut slaves = HashSet::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(name) = line.strip_prefix("Slave Interface: ") {
                slaves.insert(name.trim().to_string());
            }
        }
        slaves
    }

    fn read_vlan_parents(&self) -> HashMap<String, String> {
        let Ok(text) = std::fs::read_to_string("/proc/net/vlan/config") else {
            return HashMap::new();
        };
        let mut out = HashMap::new();
        for line in text.lines().skip(2) {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let vlan_iface = parts[0].trim_end_matches('|').to_string();
                let parent = parts[2].to_string();
                if !vlan_iface.is_empty() && !parent.is_empty() {
                    out.insert(vlan_iface, parent);
                }
            }
        }
        out
    }
}

fn read_dir_names(dir: &Path) -> HashSet<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return HashSet::new();
    };
    rd.flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.is_empty() || name == "." || name == ".." {
                None
            } else {
                Some(name)
            }
        })
        .collect()
}

pub fn discover_topology<S: TopologySource>(source: &S, ifaces: &[String]) -> NetTopology {
    let mut topo = NetTopology {
        vlan_parent: source.read_vlan_parents(),
        ..Default::default()
    };
    for iface in ifaces {
        if let Some(master) = source.read_master_link(iface) {
            topo.master_of.insert(iface.clone(), master.clone());
            if master.starts_with("br") {
                let members = source.read_bridge_members(&master);
                if !members.is_empty() {
                    topo.members_of.insert(master, members);
                }
            } else {
                let slaves = source.read_bond_slaves(&master);
                if !slaves.is_empty() {
                    topo.members_of.insert(master, slaves);
                }
            }
        }
    }
    if topo.members_of.is_empty() {
        for iface in ifaces {
            if let Some(parent) = topo.vlan_parent.get(iface) {
                topo.master_of
                    .entry(iface.clone())
                    .or_insert_with(|| parent.clone());
            }
        }
    }
    topo
}

/// Startup hints when the selected set will likely double-count traffic.
pub fn topology_duplicate_hints(selected: &[String], topo: &NetTopology) -> Vec<String> {
    if selected.len() < 2 {
        return Vec::new();
    }
    let set: HashSet<_> = selected.iter().cloned().collect();
    let mut hints = Vec::new();
    for (master, members) in &topo.members_of {
        let selected_members: Vec<_> = members.iter().filter(|m| set.contains(*m)).collect();
        if set.contains(master) && !selected_members.is_empty() {
            hints.push(format!(
                "flux: hint: {master} and its member(s) {} are both selected — packets may be \
                 counted twice; capture {master} alone or the member port(s) alone",
                selected_members
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if selected_members.len() >= 2 && !set.contains(master) {
            hints.push(format!(
                "flux: hint: bridge/bond members {} are both selected without {master} — consider \
                 a single listener",
                selected_members
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    for vlan in selected {
        if let Some(parent) = topo.vlan_parent.get(vlan) {
            if set.contains(parent) {
                hints.push(format!(
                    "flux: hint: VLAN {vlan} and parent {parent} are both selected — duplicates \
                     are likely"
                ));
            }
        }
    }
    hints.sort();
    hints.dedup();
    hints
}

/// In-memory topology for unit and integration tests.
#[derive(Default)]
pub struct MockTopology {
    pub masters: HashMap<String, String>,
    pub bridge_members: HashMap<String, HashSet<String>>,
    pub bond_slaves: HashMap<String, HashSet<String>>,
    pub vlans: HashMap<String, String>,
}

impl MockTopology {
    pub fn set_bridge(&mut self, bridge: &str, port: &str) {
        self.masters.insert(port.to_string(), bridge.to_string());
        self.bridge_members
            .entry(bridge.to_string())
            .or_default()
            .insert(port.to_string());
    }
}

impl TopologySource for MockTopology {
    fn read_master_link(&self, iface: &str) -> Option<String> {
        self.masters.get(iface).cloned()
    }

    fn read_bridge_members(&self, bridge: &str) -> HashSet<String> {
        self.bridge_members.get(bridge).cloned().unwrap_or_default()
    }

    fn read_bond_slaves(&self, bond: &str) -> HashSet<String> {
        self.bond_slaves.get(bond).cloned().unwrap_or_default()
    }

    fn read_vlan_parents(&self) -> HashMap<String, String> {
        self.vlans.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_member_hint() {
        let mut mock = MockTopology::default();
        mock.set_bridge("br0", "v0");
        mock.bridge_members
            .get_mut("br0")
            .unwrap()
            .insert("v1".into());
        let topo = discover_topology(&mock, &["br0".into(), "v0".into()]);
        let hints = topology_duplicate_hints(&["br0".into(), "v0".into()], &topo);
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("br0"));
        assert!(hints[0].contains("v0"));
    }

    #[test]
    fn bond_members_hint() {
        let mut mock = MockTopology::default();
        mock.masters.insert("eth0".into(), "bond0".into());
        mock.masters.insert("eth1".into(), "bond0".into());
        mock.bond_slaves.insert(
            "bond0".into(),
            HashSet::from(["eth0".into(), "eth1".into()]),
        );
        let topo = discover_topology(&mock, &["bond0".into(), "eth0".into(), "eth1".into()]);
        let hints = topology_duplicate_hints(&["bond0".into(), "eth0".into()], &topo);
        assert!(!hints.is_empty());
        assert!(hints[0].contains("bond0"));
    }

    #[test]
    fn vlan_parent_hint() {
        let mut mock = MockTopology::default();
        mock.vlans.insert("eth0.100".into(), "eth0".into());
        let topo = discover_topology(&mock, &["eth0".into(), "eth0.100".into()]);
        let hints = topology_duplicate_hints(&["eth0".into(), "eth0.100".into()], &topo);
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("eth0.100"));
    }
}
