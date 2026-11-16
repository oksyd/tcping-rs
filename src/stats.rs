use crate::{Counts, LatencyStats, Outcome, Probe};
use std::time::Duration;

#[derive(Clone, Debug)]
struct P2Quantile {
    p: f64,
    initial: Vec<f64>,
    n: [i64; 5],
    np: [f64; 5],
    dn: [f64; 5],
    q: [f64; 5],
    count: i64,
}

impl P2Quantile {
    fn new(p: f64) -> Self {
        Self {
            p,
            initial: Vec::with_capacity(5),
            n: [0; 5],
            np: [0.0; 5],
            dn: [0.0; 5],
            q: [0.0; 5],
            count: 0,
        }
    }

    fn estimate_from_samples(samples: &[f64], p: f64) -> Option<f64> {
        if samples.is_empty() {
            return None;
        }

        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.total_cmp(b));

        let n = sorted.len();
        if n == 1 {
            return Some(sorted[0]);
        }

        let rank = p.clamp(0.0, 1.0) * (n as f64 - 1.0);
        let lo = rank.floor() as usize;
        let hi = rank.ceil() as usize;
        if lo == hi {
            Some(sorted[lo])
        } else {
            let t = rank - lo as f64;
            Some(sorted[lo] + (sorted[hi] - sorted[lo]) * t)
        }
    }

    fn init_from_first_five(&mut self) {
        self.initial.sort_by(|a, b| a.total_cmp(b));
        for (i, v) in self.initial.iter().copied().enumerate() {
            self.q[i] = v;
            self.n[i] = (i as i64) + 1;
        }

        self.np = [
            1.0,
            1.0 + 2.0 * self.p,
            1.0 + 4.0 * self.p,
            3.0 + 2.0 * self.p,
            5.0,
        ];
        self.dn = [0.0, self.p / 2.0, self.p, (1.0 + self.p) / 2.0, 1.0];
    }

    fn observe(&mut self, x: f64) {
        if self.count < 5 {
            self.initial.push(x);
            self.count += 1;
            if self.count == 5 {
                self.init_from_first_five();
            }
            return;
        }

        self.count += 1;

        let k = if x < self.q[0] {
            self.q[0] = x;
            0
        } else if x < self.q[1] {
            0
        } else if x < self.q[2] {
            1
        } else if x < self.q[3] {
            2
        } else if x <= self.q[4] {
            3
        } else {
            self.q[4] = x;
            3
        };

        for n in self.n.iter_mut().skip(k + 1) {
            *n += 1;
        }
        for i in 0..5 {
            self.np[i] += self.dn[i];
        }

        for i in 1..=3 {
            let d = self.np[i] - self.n[i] as f64;
            if d >= 1.0 && (self.n[i + 1] - self.n[i]) > 1 {
                self.adjust_marker(i, 1);
            } else if d <= -1.0 && (self.n[i - 1] - self.n[i]) < -1 {
                self.adjust_marker(i, -1);
            }
        }
    }

    fn adjust_marker(&mut self, i: usize, sign: i64) {
        let sign_f = sign as f64;
        let n_im1 = self.n[i - 1] as f64;
        let n_i = self.n[i] as f64;
        let n_ip1 = self.n[i + 1] as f64;

        let q_im1 = self.q[i - 1];
        let q_i = self.q[i];
        let q_ip1 = self.q[i + 1];

        let q_par = q_i
            + sign_f / (n_ip1 - n_im1)
                * ((n_i - n_im1 + sign_f) * (q_ip1 - q_i) / (n_ip1 - n_i)
                    + (n_ip1 - n_i - sign_f) * (q_i - q_im1) / (n_i - n_im1));

        let q_new = if q_par > q_im1 && q_par < q_ip1 {
            q_par
        } else if sign > 0 {
            q_i + (q_ip1 - q_i) / (n_ip1 - n_i)
        } else {
            q_i - (q_i - q_im1) / (n_i - n_im1)
        };

        self.q[i] = q_new;
        self.n[i] += sign;
    }

    fn estimate(&self) -> Option<f64> {
        if self.count == 0 {
            return None;
        }

        if self.count <= 5 {
            return Self::estimate_from_samples(&self.initial, self.p);
        }

        Some(self.q[2])
    }
}

pub(crate) struct Statistics {
    counts: Counts,
    min: Duration,
    max: Duration,
    mean_ns: i128,
    mean_remainder: i128,
    previous_rtt: Option<Duration>,
    jitter_enabled: bool,
    jitter_samples: u64,
    jitter_p95: P2Quantile,
    warmup: Vec<f64>,
}

impl Statistics {
    pub(crate) fn new(jitter_enabled: bool) -> Self {
        Self {
            counts: Counts::default(),
            min: Duration::MAX,
            max: Duration::ZERO,
            mean_ns: 0,
            mean_remainder: 0,
            previous_rtt: None,
            jitter_enabled,
            jitter_samples: 0,
            jitter_p95: P2Quantile::new(0.95),
            warmup: Vec::new(),
        }
    }
    pub(crate) fn observe(&mut self, probe: &Probe) -> Option<Duration> {
        self.counts.attempted += 1;
        let rtt = match probe.outcome() {
            Outcome::Open { rtt } => {
                self.counts.open += 1;
                *rtt
            }
            Outcome::Failed(_) => {
                self.counts.failed += 1;
                return None;
            }
            Outcome::TimedOut => {
                self.counts.timed_out += 1;
                return None;
            }
            Outcome::Cancelled => {
                self.counts.cancelled += 1;
                return None;
            }
        };
        self.min = self.min.min(rtt);
        self.max = self.max.max(rtt);
        // Carry the remainder: an exact integer mean without an unbounded sum.
        let count = i128::from(self.counts.open);
        let adjustment = rtt.as_nanos() as i128 - self.mean_ns + self.mean_remainder;
        self.mean_ns += adjustment.div_euclid(count);
        self.mean_remainder = adjustment.rem_euclid(count);
        let jitter = self
            .previous_rtt
            .replace(rtt)
            .filter(|_| self.jitter_enabled)
            .map(|previous| previous.abs_diff(rtt));
        if let Some(jitter) = jitter {
            self.jitter_samples += 1;
            let milliseconds = jitter.as_secs_f64() * 1000.0;
            self.jitter_p95.observe(milliseconds);
            if self.jitter_samples <= 100 {
                self.warmup.push(milliseconds);
            }
        }
        jitter
    }
    pub(crate) fn counts(&self) -> Counts {
        self.counts
    }
    pub(crate) fn latency(&self) -> Option<LatencyStats> {
        (self.counts.open != 0).then(|| LatencyStats {
            min: self.min,
            average: Duration::new(
                (self.mean_ns / 1_000_000_000) as u64,
                (self.mean_ns % 1_000_000_000) as u32,
            ),
            max: self.max,
        })
    }
    pub(crate) fn jitter_samples(&self) -> u64 {
        self.jitter_samples
    }
    pub(crate) fn jitter_p95(&self) -> Option<Duration> {
        let milliseconds = if self.jitter_samples <= 100 {
            P2Quantile::estimate_from_samples(&self.warmup, 0.95)
        } else {
            self.jitter_p95.estimate()
        }?;
        Duration::try_from_secs_f64(milliseconds / 1000.0).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Failure;
    use std::{io, time::UNIX_EPOCH};

    fn probe(elapsed: Duration, outcome: Outcome) -> Probe {
        Probe {
            mode: crate::ProbeMode::Connect,
            sequence: 1,
            address: "127.0.0.1:443".parse().unwrap(),
            started_at: UNIX_EPOCH,
            elapsed,
            timeout: Duration::from_secs(2),
            outcome,
            jitter: None,
        }
    }

    fn open(rtt: Duration) -> Probe {
        probe(rtt, Outcome::Open { rtt })
    }

    #[test]
    fn no_completed_connections_have_no_latency_or_failure_rate() {
        let mut stats = Statistics::new(true);
        assert!(stats.latency().is_none());
        assert!(stats.jitter_p95().is_none());
        stats.observe(&probe(Duration::from_millis(50), Outcome::Cancelled));
        assert_eq!(stats.counts().failure_ratio(), None);
        assert!(stats.latency().is_none());
    }

    #[test]
    fn failures_are_excluded_and_zero_rtt_is_a_valid_sample() {
        let mut stats = Statistics::new(true);
        stats.observe(&open(Duration::ZERO));
        stats.observe(&probe(Duration::from_secs(2), Outcome::TimedOut));
        stats.observe(&probe(
            Duration::from_secs(1),
            Outcome::Failed(Failure::from_io(io::ErrorKind::ConnectionRefused.into())),
        ));
        assert_eq!(
            stats.observe(&open(Duration::from_millis(40))),
            Some(Duration::from_millis(40))
        );
        let latency = stats.latency().unwrap();
        assert_eq!(latency.min(), Duration::ZERO);
        assert_eq!(latency.average(), Duration::from_millis(20));
        assert_eq!(latency.max(), Duration::from_millis(40));
        assert_eq!(stats.counts().failure_ratio(), Some(0.5));
    }

    #[test]
    fn integer_mean_does_not_accumulate_rounding_error() {
        let mut stats = Statistics::new(false);
        stats.observe(&open(Duration::ZERO));
        for _ in 0..1000 {
            stats.observe(&open(Duration::from_nanos(10)));
        }
        assert_eq!(stats.latency().unwrap().average(), Duration::from_nanos(9));
        for _ in 0..1000 {
            stats.observe(&open(Duration::ZERO));
        }
        assert_eq!(stats.latency().unwrap().average(), Duration::from_nanos(4));
    }

    #[test]
    fn jitter_can_be_disabled_without_affecting_rtt() {
        let mut stats = Statistics::new(false);
        for ms in [10, 40, 25] {
            assert_eq!(stats.observe(&open(Duration::from_millis(ms))), None);
        }
        assert_eq!(
            stats.latency().unwrap().average(),
            Duration::from_millis(25)
        );
        assert_eq!(stats.jitter_samples(), 0);
        assert_eq!(stats.jitter_p95(), None);
        assert!(stats.warmup.is_empty());
    }

    #[test]
    fn p95_is_exact_during_warmup_then_uses_bounded_storage() {
        let mut stats = Statistics::new(true);
        let mut rtt = 0;
        stats.observe(&open(Duration::ZERO));
        for jitter in 1..=10_000 {
            rtt += jitter;
            stats.observe(&open(Duration::from_micros(rtt)));
            if jitter == 100 {
                assert_eq!(stats.jitter_p95(), Some(Duration::from_nanos(95_050)));
            }
        }
        let p95 = stats.jitter_p95().unwrap().as_micros();
        assert!((9400..=9600).contains(&p95), "p95 = {p95}");
        assert_eq!(stats.warmup.len(), 100);
        assert_eq!(stats.jitter_p95.initial.len(), 5);
    }

    #[test]
    fn quantile_handles_constant_and_nonmonotonic_samples() {
        let mut constant = P2Quantile::new(0.95);
        let mut shuffled = P2Quantile::new(0.95);
        let mut samples = Vec::new();
        for index in 0..10_000 {
            constant.observe(0.0);
            let sample = ((index * 7919) % 10_000) as f64;
            samples.push(sample);
            shuffled.observe(sample);
        }
        assert_eq!(constant.estimate(), Some(0.0));
        let exact = P2Quantile::estimate_from_samples(&samples, 0.95).unwrap();
        assert!((shuffled.estimate().unwrap() - exact).abs() < 100.0);
    }
}
