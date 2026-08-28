use dns_resolve::{NodePath, TraceHop, TraceProgress};

use crate::hop_display::print_hop_human;

pub struct StderrProgress {
    events: bool,
}

impl StderrProgress {
    pub fn new(events: bool) -> Self {
        Self { events }
    }
}

impl TraceProgress for StderrProgress {
    fn hop(&mut self, hop: &TraceHop, path: &NodePath) {
        if self.events {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "event": "hop",
                    "tree": path.tree,
                    "path": path.path,
                    "hop": hop,
                }))
                .expect("json")
            );
            return;
        }

        print_hop_human(hop, path.path.len());
    }

    fn message(&mut self, message: &str) {
        if self.events {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "event": "message",
                    "message": message,
                }))
                .expect("json")
            );
        } else {
            eprintln!("  -> {message}");
        }
    }

    fn budget_truncated(&mut self, cap: usize) {
        if self.events {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "event": "budget",
                    "cap": cap,
                    "message": format!("query budget of {cap} exhausted; trace truncated"),
                }))
                .expect("json")
            );
        } else {
            eprintln!("  -> query budget of {cap} exhausted; trace truncated");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, NodeOrigin, TraceHop, TraceNode, TraceTree, TraceTreeRequest};

    #[test]
    fn events_emit_tree_path_fields() {
        let mut progress = StderrProgress::new(true);
        let hop = TraceHop {
            zone: ".".into(),
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
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        };
        progress.hop(
            &hop,
            &NodePath {
                tree: 0,
                path: vec![0, 1],
            },
        );
        progress.budget_truncated(64);
    }

    #[test]
    fn hop_events_rebuild_tree_matching_complete() {
        let request = TraceTreeRequest {
            qname: "example.com.".into(),
            qtype: "A".into(),
            started_at: "2026-01-01T00:00:00Z".into(),
        };
        let complete = TraceTree {
            request: request.clone(),
            root: TraceNode {
                hop: sample_hop("root"),
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: sample_hop("left"),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: sample_hop("right"),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            },
            budget_truncated: false,
        };

        let mut rebuilt_root: Option<TraceNode> = None;
        let mut progress = RebuildProgress {
            root: &mut rebuilt_root,
        };
        for path in complete.display_order() {
            if let Some(node) = complete.resolve(&path) {
                progress.hop(&node.hop, &path);
            }
        }

        let rebuilt = TraceTree {
            request,
            root: rebuilt_root.expect("root"),
            budget_truncated: false,
        };
        assert_eq!(rebuilt, complete);
    }

    fn sample_hop(label: &str) -> TraceHop {
        TraceHop {
            zone: ".".into(),
            server: "1.1.1.1".into(),
            server_name: None,
            qname: label.into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 1,
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

    struct RebuildProgress<'a> {
        root: &'a mut Option<TraceNode>,
    }

    impl TraceProgress for RebuildProgress<'_> {
        fn hop(&mut self, hop: &TraceHop, path: &NodePath) {
            insert_hop(self.root, path, hop.clone());
        }

        fn message(&mut self, _message: &str) {}
    }

    fn insert_hop(root: &mut Option<TraceNode>, path: &NodePath, hop: TraceHop) {
        if path.path.is_empty() {
            *root = Some(TraceNode {
                hop,
                origin: NodeOrigin::Trace,
                children: vec![],
            });
            return;
        }

        let root = root.get_or_insert_with(|| TraceNode {
            hop: hop.clone(),
            origin: NodeOrigin::Trace,
            children: vec![],
        });

        let mut node = root;
        for (depth, &index) in path.path.iter().enumerate() {
            if depth + 1 == path.path.len() {
                while node.children.len() <= index {
                    node.children.push(TraceNode {
                        hop: hop.clone(),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    });
                }
                node.children[index].hop = hop;
                return;
            }
            while node.children.len() <= index {
                node.children.push(TraceNode {
                    hop: hop.clone(),
                    origin: NodeOrigin::Trace,
                    children: vec![],
                });
            }
            node = &mut node.children[index];
        }
    }
}
