use crate::{HopOutcome, NodeOrigin, TraceHop, TraceNode};

#[derive(Debug, Default)]
pub struct ResultStore {
    root: Option<TraceNode>,
}

impl ResultStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_hop(&mut self, path: &[usize], hop: TraceHop, origin: NodeOrigin) {
        let node = TraceNode {
            hop,
            origin,
            children: Vec::new(),
        };
        if path.is_empty() {
            self.root = Some(node);
            return;
        }

        let root = self.root.get_or_insert_with(|| TraceNode {
            hop: placeholder_hop(),
            origin: NodeOrigin::Trace,
            children: Vec::new(),
        });
        let parent = resolve_mut(root, &path[..path.len() - 1]);
        let child_index = *path.last().expect("non-empty path");
        if parent.children.len() <= child_index {
            parent.children.resize(
                child_index + 1,
                TraceNode {
                    hop: placeholder_hop(),
                    origin: NodeOrigin::Trace,
                    children: Vec::new(),
                },
            );
        }
        parent.children[child_index] = node;
    }

    pub fn take_tree(&mut self) -> Option<TraceNode> {
        self.root.take()
    }

    pub fn node_at(&self, path: &[usize]) -> Option<TraceNode> {
        self.root.as_ref().map(|root| node_at_path(root, path))
    }

    pub fn children_at(&self, parent_path: &[usize]) -> Vec<TraceNode> {
        let Some(root) = &self.root else {
            return Vec::new();
        };
        let parent = if parent_path.is_empty() {
            root
        } else if let Some(node) = node_at_path_ref(root, parent_path) {
            node
        } else {
            return Vec::new();
        };
        parent.children.clone()
    }
}

fn node_at_path_ref<'a>(root: &'a TraceNode, path: &[usize]) -> Option<&'a TraceNode> {
    let mut node = root;
    for &index in path {
        node = node.children.get(index)?;
    }
    Some(node)
}

fn node_at_path(root: &TraceNode, path: &[usize]) -> TraceNode {
    node_at_path_ref(root, path)
        .cloned()
        .unwrap_or_else(|| TraceNode {
            hop: placeholder_hop(),
            origin: NodeOrigin::Trace,
            children: Vec::new(),
        })
}

fn resolve_mut<'a>(root: &'a mut TraceNode, path: &[usize]) -> &'a mut TraceNode {
    let mut node = root;
    for &index in path {
        if node.children.len() <= index {
            node.children.resize(
                index + 1,
                TraceNode {
                    hop: placeholder_hop(),
                    origin: NodeOrigin::Trace,
                    children: Vec::new(),
                },
            );
        }
        node = &mut node.children[index];
    }
    node
}

fn placeholder_hop() -> TraceHop {
    TraceHop {
        zone: ".".into(),
        server: "0.0.0.0".into(),
        server_name: None,
        qname: ".".into(),
        qtype: "A".into(),
        transport: "udp".into(),
        rtt_ms: 0,
        rcode: "NOERROR".into(),
        nsid: None,
        ede_code: None,
        ede_text: None,
        referral_ns: vec![],
        glue: vec![],
        response: Default::default(),
        from_cache: false,
        outcome: HopOutcome::Referral,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StoredDnsMessage;

    fn hop_at(zone: &str) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: "1.1.1.1".into(),
            server_name: None,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 1,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: StoredDnsMessage::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        }
    }

    #[test]
    fn inserts_at_root_and_child_paths() {
        let mut store = ResultStore::new();
        store.insert_hop(&[], hop_at("."), NodeOrigin::Trace);
        store.insert_hop(&[0], hop_at("com."), NodeOrigin::Trace);
        store.insert_hop(&[1], hop_at("org."), NodeOrigin::Trace);

        let root = store.take_tree().expect("root");
        assert_eq!(root.hop.zone, ".");
        assert_eq!(root.children.len(), 2);
        assert_eq!(root.children[0].hop.zone, "com.");
        assert_eq!(root.children[1].hop.zone, "org.");
    }
}
