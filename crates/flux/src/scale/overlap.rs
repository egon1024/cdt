use std::collections::{HashMap, HashSet};

const SAMPLE_SHIFT: u32 = 6; // 1 in 64

#[derive(Debug, Default, Clone)]
pub struct OverlapTracker {
    samples: HashMap<u64, HashSet<String>>,
    iface_totals: HashMap<String, u64>,
    sample_in: u64,
}

impl OverlapTracker {
    pub fn observe(&mut self, fp: u64, iface: &str) {
        *self.iface_totals.entry(iface.to_string()).or_insert(0) += 1;
        let in_bucket = (fp & ((1u64 << SAMPLE_SHIFT) - 1)) == 0;
        let seen_other_iface = self
            .samples
            .get(&fp)
            .is_some_and(|ifaces| !ifaces.contains(iface));
        let is_repeat = self.samples.contains_key(&fp);
        if !in_bucket && !seen_other_iface && !is_repeat {
            return;
        }
        self.sample_in = self.sample_in.saturating_add(1);
        self.samples
            .entry(fp)
            .or_default()
            .insert(iface.to_string());
    }

    /// Pairwise overlap as percentage of sampled packets seen on both interfaces (Jaccard).
    pub fn pairwise_overlap_pct(&self) -> Vec<((String, String), f64)> {
        let ifaces: Vec<_> = self.iface_totals.keys().cloned().collect();
        if ifaces.len() < 2 {
            return Vec::new();
        }
        let mut pair_both = HashMap::<(String, String), u64>::new();
        for seen in self.samples.values() {
            let list: Vec<_> = seen.iter().cloned().collect();
            for i in 0..list.len() {
                for j in (i + 1)..list.len() {
                    let a = &list[i];
                    let b = &list[j];
                    let key = if a < b {
                        (a.clone(), b.clone())
                    } else {
                        (b.clone(), a.clone())
                    };
                    *pair_both.entry(key).or_insert(0) += 1;
                }
            }
        }
        let mut out = Vec::new();
        for i in 0..ifaces.len() {
            for j in (i + 1)..ifaces.len() {
                let a = &ifaces[i];
                let b = &ifaces[j];
                let key = if a < b {
                    (a.clone(), b.clone())
                } else {
                    (b.clone(), a.clone())
                };
                let both = *pair_both.get(&key).unwrap_or(&0);
                let only_a = self
                    .samples
                    .values()
                    .filter(|s| s.contains(a) && !s.contains(b))
                    .count() as u64;
                let only_b = self
                    .samples
                    .values()
                    .filter(|s| s.contains(b) && !s.contains(a))
                    .count() as u64;
                let union = both.saturating_add(only_a).saturating_add(only_b);
                let pct = if union == 0 {
                    0.0
                } else {
                    (both as f64) * 100.0 / union as f64
                };
                if pct > 0.0 {
                    out.push((key, pct));
                }
            }
        }
        out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        out
    }

    pub fn format_listener_lines(&self) -> Vec<String> {
        let mut lines = vec!["--- listeners overlap (sampled) ---".to_string()];
        for ((a, b), pct) in self.pairwise_overlap_pct() {
            lines.push(format!("  {a} × {b}: {pct:.0}%"));
        }
        if lines.len() == 1 {
            lines.push("  (no multi-interface samples yet)".into());
        }
        lines
    }

    pub fn high_overlap_hint(&self, threshold_pct: f64) -> Option<String> {
        self
      .pairwise_overlap_pct()
      .into_iter()
      .find(|(_, pct)| *pct >= threshold_pct)
      .map(|((a, b), pct)| {
        format!(
          "flux: hint: high overlap ({pct:.0}%) between {a} and {b} — consider capturing one \
           interface or enabling +dedup"
        )
      })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_on_duplicate_fingerprints() {
        let mut t = OverlapTracker::default();
        let fp = 0x40; // sample: low 6 bits zero
        t.observe(fp, "br0");
        t.observe(fp, "v0");
        let pairs = t.pairwise_overlap_pct();
        assert!(!pairs.is_empty());
        let (_, pct) = &pairs[0];
        assert!(*pct >= 99.0, "pct={pct}");
    }
}
