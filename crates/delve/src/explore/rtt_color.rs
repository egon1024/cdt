use crate::config::RttBarConfig;

const GREEN: (u8, u8, u8) = (72, 198, 108);
const YELLOW: (u8, u8, u8) = (255, 214, 48);
const ORANGE: (u8, u8, u8) = (255, 132, 32);
const RED: (u8, u8, u8) = (214, 48, 48);

pub fn rtt_gradient_rgb(rtt_ms: u32, config: RttBarConfig) -> (u8, u8, u8) {
    let config = config.normalized();
    if rtt_ms <= config.green_ms {
        return GREEN;
    }
    if rtt_ms <= config.yellow_ms {
        let span = config.yellow_ms - config.green_ms;
        let t = (rtt_ms - config.green_ms) as f32 / span as f32;
        return lerp_rgb(GREEN, YELLOW, t);
    }
    if rtt_ms <= config.orange_ms {
        let span = config.orange_ms - config.yellow_ms;
        let t = (rtt_ms - config.yellow_ms) as f32 / span as f32;
        return lerp_rgb(YELLOW, ORANGE, t);
    }
    if rtt_ms <= config.insane_ms {
        let span = config.insane_ms - config.orange_ms;
        let t = (rtt_ms - config.orange_ms) as f32 / span as f32;
        return lerp_rgb(ORANGE, RED, t);
    }
    RED
}

fn lerp_rgb(start: (u8, u8, u8), end: (u8, u8, u8), t: f32) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0);
    (
        lerp_channel(start.0, end.0, t),
        lerp_channel(start.1, end.1, t),
        lerp_channel(start.2, end.2, t),
    )
}

fn lerp_channel(start: u8, end: u8, t: f32) -> u8 {
    (f32::from(start) + (f32::from(end) - f32::from(start)) * t).round() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RttBarConfig {
        RttBarConfig::default()
    }

    #[test]
    fn gradient_matches_explore_thresholds() {
        let cfg = config();
        assert_eq!(rtt_gradient_rgb(0, cfg), GREEN);
        assert_eq!(rtt_gradient_rgb(23, cfg), GREEN);
        assert_eq!(rtt_gradient_rgb(cfg.green_ms, cfg), GREEN);
        assert_eq!(rtt_gradient_rgb(cfg.yellow_ms, cfg), YELLOW);
        assert_eq!(rtt_gradient_rgb(cfg.orange_ms, cfg), ORANGE);
        assert_eq!(rtt_gradient_rgb(cfg.insane_ms, cfg), RED);
    }

    #[test]
    fn gradient_transitions_between_milestones() {
        let cfg = config();
        let mid_yellow = rtt_gradient_rgb(87, cfg);
        assert!(mid_yellow.0 > GREEN.0);
        assert!(mid_yellow.1 < YELLOW.1);
    }
}
