use std::collections::HashMap;

use crate::{NodePath, TraceHop, TraceProgress};

#[derive(Debug, Default)]
pub struct EmitScheduler {
    order: Vec<Vec<usize>>,
    ready: HashMap<Vec<usize>, TraceHop>,
    next_index: usize,
}

impl EmitScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_path(&mut self, path: Vec<usize>) {
        self.order.push(path);
    }

    pub fn mark_ready(&mut self, path: &[usize], hop: TraceHop) {
        self.ready.insert(path.to_vec(), hop);
    }

    pub fn drain(&mut self, progress: &mut dyn TraceProgress) {
        while self.next_index < self.order.len() {
            let expected = self.order[self.next_index].clone();
            let Some(hop) = self.ready.remove(&expected) else {
                break;
            };
            let node_path = NodePath {
                tree: 0,
                path: expected,
            };
            progress.hop(&hop, &node_path);
            self.next_index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HopOutcome, StoredDnsMessage};

    struct RecordingProgress {
        paths: Vec<Vec<usize>>,
    }

    impl TraceProgress for RecordingProgress {
        fn hop(&mut self, _hop: &TraceHop, path: &NodePath) {
            self.paths.push(path.path.clone());
        }

        fn message(&mut self, _message: &str) {}
    }

    fn hop() -> TraceHop {
        TraceHop {
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
            response: StoredDnsMessage::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        }
    }

    #[test]
    fn emits_in_path_order_even_when_later_path_finishes_first() {
        let mut scheduler = EmitScheduler::new();
        scheduler.register_path(vec![0]);
        scheduler.register_path(vec![1]);
        let mut progress = RecordingProgress { paths: vec![] };

        scheduler.mark_ready(&[1], hop());
        scheduler.drain(&mut progress);
        assert!(progress.paths.is_empty());

        scheduler.mark_ready(&[0], hop());
        scheduler.drain(&mut progress);
        assert_eq!(progress.paths, vec![vec![0], vec![1]]);
    }
}
