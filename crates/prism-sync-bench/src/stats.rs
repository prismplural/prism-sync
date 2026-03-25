use hdrhistogram::Histogram;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpType {
    Register,
    Push,
    Pull,
    Ack,
    WsConnect,
}

impl OpType {
    fn label(&self) -> &'static str {
        match self {
            OpType::Register => "Register",
            OpType::Push => "Push",
            OpType::Pull => "Pull",
            OpType::Ack => "Ack",
            OpType::WsConnect => "WsConnect",
        }
    }
}

struct OpStats {
    histogram: Mutex<Histogram<u64>>,
    errors: AtomicU64,
}

pub struct Stats {
    start: Instant,
    ops: HashMap<OpType, OpStats>,
}

impl Stats {
    pub fn new() -> Self {
        let mut ops = HashMap::new();
        for op in [
            OpType::Register,
            OpType::Push,
            OpType::Pull,
            OpType::Ack,
            OpType::WsConnect,
        ] {
            ops.insert(
                op,
                OpStats {
                    histogram: Mutex::new(Histogram::new(3).unwrap()),
                    errors: AtomicU64::new(0),
                },
            );
        }
        Self {
            start: Instant::now(),
            ops,
        }
    }

    pub fn record(&self, op: OpType, elapsed: Duration) {
        let micros = elapsed.as_micros() as u64;
        if let Some(s) = self.ops.get(&op) {
            let _ = s.histogram.lock().unwrap().record(micros);
        }
    }

    pub fn record_error(&self, op: OpType) {
        if let Some(s) = self.ops.get(&op) {
            s.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn print_progress(&self) {
        let elapsed = self.elapsed().as_secs();
        let mut parts = Vec::new();
        for op in [OpType::Push, OpType::Pull] {
            if let Some(s) = self.ops.get(&op) {
                let h = s.histogram.lock().unwrap();
                let count = h.len();
                if count > 0 {
                    let rate = count as f64 / self.elapsed().as_secs_f64();
                    let p99 = h.value_at_quantile(0.99) as f64 / 1000.0;
                    parts.push(format!(
                        "{}: {:.0}/s p99={:.1}ms",
                        op.label().to_lowercase(),
                        rate,
                        p99
                    ));
                }
            }
        }
        let total_errors: u64 = self
            .ops
            .values()
            .map(|s| s.errors.load(Ordering::Relaxed))
            .sum();
        if parts.is_empty() {
            println!("[{elapsed}s] running...  errors: {total_errors}");
        } else {
            println!(
                "[{elapsed}s] {}  errors: {total_errors}",
                parts.join("  ")
            );
        }
    }

    pub fn print_ws_progress(&self, connected: usize, target: usize) {
        let elapsed = self.elapsed().as_secs();
        let total_errors: u64 = self
            .ops
            .values()
            .map(|s| s.errors.load(Ordering::Relaxed))
            .sum();
        let mut p99_str = String::new();
        if let Some(s) = self.ops.get(&OpType::WsConnect) {
            let h = s.histogram.lock().unwrap();
            if h.len() > 0 {
                p99_str = format!(
                    "  connect_p99={:.1}ms",
                    h.value_at_quantile(0.99) as f64 / 1000.0
                );
            }
        }
        println!("[{elapsed}s] ws: {connected}/{target}{p99_str}  errors: {total_errors}");
    }

    pub fn print_summary(&self, title: &str, extra: &str) {
        println!("\n=== {title} Results ===");
        println!("Duration: {:.1}s", self.elapsed().as_secs_f64());
        if !extra.is_empty() {
            println!("{extra}");
        }
        println!();

        for op in [
            OpType::Register,
            OpType::WsConnect,
            OpType::Push,
            OpType::Pull,
            OpType::Ack,
        ] {
            if let Some(s) = self.ops.get(&op) {
                let h = s.histogram.lock().unwrap();
                let count = h.len();
                if count == 0 {
                    continue;
                }
                let rate = count as f64 / self.elapsed().as_secs_f64();
                let errors = s.errors.load(Ordering::Relaxed);
                let p50 = h.value_at_quantile(0.5) as f64 / 1000.0;
                let p95 = h.value_at_quantile(0.95) as f64 / 1000.0;
                let p99 = h.value_at_quantile(0.99) as f64 / 1000.0;
                let max = h.max() as f64 / 1000.0;
                println!(
                    "{:<10} total={:<6}  rate={:.0}/s  p50={:.1}ms  p95={:.1}ms  p99={:.1}ms  max={:.1}ms  errors={}",
                    format!("{}:", op.label()),
                    count,
                    rate,
                    p50,
                    p95,
                    p99,
                    max,
                    errors
                );
            }
        }

        let total_errors: u64 = self
            .ops
            .values()
            .map(|s| s.errors.load(Ordering::Relaxed))
            .sum();
        println!("\nTotal errors: {total_errors}");
    }
}
