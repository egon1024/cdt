use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct ListenerMeasurements {
    pub iface: String,
    pub rate_pps: f64,
    pub drops: u64,
    pub capture_threads: u32,
    pub capture_busy_pct: u8,
    pub capture_queue: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseThreadMeasurements {
    pub busy_pct: u8,
    pub queue_depth: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hint {
    CaptureDrops { iface: String },
    FlowSaturated,
    ParseSaturated { workers: usize },
    HotFlowBucket { bucket: u32 },
    AddWorkers,
}

const PARSE_BUSY_THRESHOLD: u8 = 85;
const QUEUE_DEPTH_THRESHOLD: u64 = 100;
const DROP_THRESHOLD: u64 = 1;

#[derive(Debug, Default)]
pub struct HintEngine {
    pub thresholds_parse_busy: u8,
    pub thresholds_queue: u64,
}

impl HintEngine {
    pub fn new() -> Self {
        Self {
            thresholds_parse_busy: PARSE_BUSY_THRESHOLD,
            thresholds_queue: QUEUE_DEPTH_THRESHOLD,
        }
    }

    pub fn evaluate(
        &self,
        listeners: &[ListenerMeasurements],
        parse_threads: &[ParseThreadMeasurements],
        flow_busy_pct: u8,
        hot_bucket: Option<u32>,
    ) -> Vec<Hint> {
        let mut hints = Vec::new();
        for l in listeners {
            if l.drops >= DROP_THRESHOLD {
                hints.push(Hint::CaptureDrops {
                    iface: l.iface.clone(),
                });
            }
        }
        if flow_busy_pct >= PARSE_BUSY_THRESHOLD {
            hints.push(Hint::FlowSaturated);
        }
        let saturated = parse_threads.iter().any(|p| {
            p.busy_pct >= self.thresholds_parse_busy || p.queue_depth >= self.thresholds_queue
        });
        if saturated {
            hints.push(Hint::ParseSaturated {
                workers: parse_threads.len(),
            });
            hints.push(Hint::AddWorkers);
        }
        if let Some(bucket) = hot_bucket {
            hints.push(Hint::HotFlowBucket { bucket });
        }
        hints
    }

    pub fn format_hints(hints: &[Hint]) -> Vec<String> {
        hints
            .iter()
            .map(|h| match h {
                Hint::CaptureDrops { iface } => {
                    format!("hint: capture drops on {iface} — check fanout or NIC load")
                }
                Hint::FlowSaturated => "hint: flow stage saturated — consider +flow-threads".into(),
                Hint::ParseSaturated { workers } => {
                    format!("hint: parse workers busy (n={workers}) — press '+' to add workers")
                }
                Hint::HotFlowBucket { bucket } => format!(
                    "hint: hot flow bucket {bucket} — traffic may be crafted or one pair dominates"
                ),
                Hint::AddWorkers => "hint: add parse workers with '+'".into(),
            })
            .collect()
    }
}

pub fn bucket_load_histogram(
    buckets: u32,
    assignments: impl Iterator<Item = u32>,
) -> HashMap<u32, u64> {
    let mut hist = HashMap::new();
    for b in assignments {
        if b < buckets {
            *hist.entry(b).or_insert(0) += 1;
        }
    }
    hist
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_saturation_hint() {
        let engine = HintEngine::new();
        let hints = engine.evaluate(
            &[],
            &[ParseThreadMeasurements {
                busy_pct: 95,
                queue_depth: 0,
            }],
            10,
            None,
        );
        assert!(hints.iter().any(|h| matches!(h, Hint::AddWorkers)));
    }

    #[test]
    fn capture_drop_hint() {
        let engine = HintEngine::new();
        let hints = engine.evaluate(
            &[ListenerMeasurements {
                iface: "eth0".into(),
                rate_pps: 100.0,
                drops: 5,
                capture_threads: 1,
                capture_busy_pct: 10,
                capture_queue: 0,
            }],
            &[],
            0,
            None,
        );
        assert!(
            hints
                .iter()
                .any(|h| matches!(h, Hint::CaptureDrops { iface } if iface == "eth0"))
        );
    }
}
