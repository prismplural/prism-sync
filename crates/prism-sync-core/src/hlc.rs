use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{CoreError, Result};

/// Maximum accepted HLC node id length in bytes.
///
/// Local node ids are documented as 12-char hex strings. This bound is
/// intentionally more generous to avoid rejecting legacy/test ids while still
/// preventing unbounded remote input from amplifying storage and comparisons.
pub const MAX_NODE_ID_LEN: usize = 64;

/// Hybrid Logical Clock for CRDT sync.
///
/// Format: `timestamp:counter:nodeId`
/// - timestamp: Unix milliseconds (i64)
/// - counter: monotonic counter for same-timestamp events (u32)
/// - node_id: unique device identifier (12-char hex string)
///
/// Ported from Dart `lib/core/sync/hlc.dart`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Hlc {
    pub timestamp: i64,
    pub counter: u32,
    pub node_id: String,
}

impl Hlc {
    /// Create an HLC with explicit values.
    pub fn new(timestamp: i64, counter: u32, node_id: impl Into<String>) -> Self {
        Self { timestamp, counter, node_id: node_id.into() }
    }

    /// Create a zero-valued HLC (used as initial state).
    pub fn zero(node_id: impl Into<String>) -> Self {
        Self { timestamp: 0, counter: 0, node_id: node_id.into() }
    }

    /// Parse HLC from string format "timestamp:counter:nodeId".
    ///
    /// An empty string returns a zero-valued HLC with an empty node_id
    /// (matching Dart behavior).
    pub fn from_string(hlc_string: &str) -> Result<Self> {
        if hlc_string.is_empty() {
            return Ok(Self { timestamp: 0, counter: 0, node_id: String::new() });
        }

        let parts: Vec<&str> = hlc_string.split(':').collect();
        if parts.len() != 3 {
            return Err(CoreError::HlcParse(format!(
                "Invalid HLC format (expected 3 colon-separated parts): {hlc_string}"
            )));
        }

        let timestamp = parts[0]
            .parse::<i64>()
            .map_err(|e| CoreError::HlcParse(format!("Invalid timestamp '{}': {e}", parts[0])))?;
        if timestamp < 0 {
            return Err(CoreError::HlcParse(format!("Invalid timestamp '{}': negative", parts[0])));
        }

        let counter = parts[1]
            .parse::<u32>()
            .map_err(|e| CoreError::HlcParse(format!("Invalid counter '{}': {e}", parts[1])))?;

        if parts[2].len() > MAX_NODE_ID_LEN {
            return Err(CoreError::HlcParse(format!(
                "Invalid node_id length {} (max {MAX_NODE_ID_LEN})",
                parts[2].len()
            )));
        }
        let node_id = parts[2].to_string();

        Ok(Self { timestamp, counter, node_id })
    }

    /// Get current wall-clock time in milliseconds since Unix epoch.
    pub(crate) fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_millis() as i64
    }

    /// Create a new HLC for the current time on this node.
    ///
    /// If `last_known` is provided and its timestamp >= wall clock,
    /// the counter is incremented instead of resetting to 0.
    pub fn now(node_id: &str, last_known: Option<&Hlc>) -> Self {
        let now = Self::now_ms();

        match last_known {
            None => Self { timestamp: now, counter: 0, node_id: node_id.to_string() },
            Some(last) if now > last.timestamp => {
                Self { timestamp: now, counter: 0, node_id: node_id.to_string() }
            }
            Some(last) => Self {
                timestamp: last.timestamp,
                counter: last.counter + 1,
                node_id: node_id.to_string(),
            },
        }
    }

    /// Merge this HLC with a received remote HLC.
    /// Returns a new HLC that is causally after both.
    ///
    /// Algorithm (matching Dart implementation exactly):
    /// 1. max_ts = max(now, self.timestamp, remote.timestamp)
    /// 2. If max_ts == self.timestamp == remote.timestamp:
    ///    counter = max(self.counter, remote.counter) + 1
    /// 3. Else if max_ts == self.timestamp:
    ///    counter = self.counter + 1
    /// 4. Else if max_ts == remote.timestamp:
    ///    counter = remote.counter + 1
    /// 5. Else (max_ts == now, wall clock advanced):
    ///    counter = 0
    pub fn merge(&self, remote: &Hlc, local_node_id: &str) -> Self {
        let now = Self::now_ms();
        let max_ts = now.max(self.timestamp).max(remote.timestamp);

        let new_counter = if max_ts == self.timestamp && max_ts == remote.timestamp {
            self.counter.max(remote.counter) + 1
        } else if max_ts == self.timestamp {
            self.counter + 1
        } else if max_ts == remote.timestamp {
            remote.counter + 1
        } else {
            0
        };

        Self { timestamp: max_ts, counter: new_counter, node_id: local_node_id.to_string() }
    }

    /// Parse a slice of HLC strings and return the max per `Hlc::Ord`.
    ///
    /// Returns `Ok(None)` if the slice is empty. The first parse error is
    /// propagated — callers are expected to pass well-formed HLC strings
    /// read from `field_versions`.
    ///
    /// This exists because a SQL `MAX(winning_hlc)` compares strings
    /// lexicographically and gets the order wrong for counters: `":9"`
    /// sorts after `":10"`. Callers that need the true HLC max must read
    /// all candidate strings and compare them here.
    pub fn parse_many_and_max(values: &[String]) -> Result<Option<Hlc>> {
        let mut best: Option<Hlc> = None;
        for v in values {
            let parsed = Self::from_string(v)?;
            best = Some(match best {
                Some(cur) if cur >= parsed => cur,
                _ => parsed,
            });
        }
        Ok(best)
    }

    /// Check if clock drift exceeds the given tolerance.
    ///
    /// Only rejects timestamps from the FUTURE beyond the tolerance.
    /// Past timestamps are always accepted — old data is normal in a CRDT.
    pub fn is_drift_exceeded(&self, max_drift_ms: i64) -> bool {
        self.future_drift_ms() > max_drift_ms.max(0)
    }

    /// Return how far this HLC is ahead of local wall-clock time.
    ///
    /// Past or current timestamps return 0.
    pub fn future_drift_ms(&self) -> i64 {
        self.timestamp.saturating_sub(Self::now_ms()).max(0)
    }

    /// Return true when this HLC is ahead of local wall-clock time.
    pub fn is_future(&self) -> bool {
        self.future_drift_ms() > 0
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.counter.cmp(&other.counter))
            .then_with(|| self.node_id.cmp(&other.node_id))
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.timestamp, self.counter, self.node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_hlc() {
        let hlc = Hlc::from_string("1710500000000:5:a1b2c3d4e5f6").unwrap();
        assert_eq!(hlc.timestamp, 1710500000000);
        assert_eq!(hlc.counter, 5);
        assert_eq!(hlc.node_id, "a1b2c3d4e5f6");
    }

    #[test]
    fn parse_empty_string() {
        let hlc = Hlc::from_string("").unwrap();
        assert_eq!(hlc.timestamp, 0);
        assert_eq!(hlc.counter, 0);
        assert_eq!(hlc.node_id, "");
    }

    #[test]
    fn parse_invalid_format_two_parts() {
        assert!(Hlc::from_string("123:456").is_err());
    }

    #[test]
    fn parse_invalid_format_four_parts() {
        assert!(Hlc::from_string("1:2:3:4").is_err());
    }

    #[test]
    fn parse_invalid_timestamp() {
        assert!(Hlc::from_string("notanumber:0:node").is_err());
    }

    #[test]
    fn parse_rejects_negative_timestamp() {
        assert!(Hlc::from_string("-1:0:node").is_err());
    }

    #[test]
    fn parse_invalid_counter() {
        assert!(Hlc::from_string("1000:notanumber:node").is_err());
    }

    #[test]
    fn parse_rejects_overlong_node_id() {
        let overlong = "a".repeat(MAX_NODE_ID_LEN + 1);
        assert!(Hlc::from_string(&format!("1000:0:{overlong}")).is_err());
    }

    #[test]
    fn parse_accepts_max_length_node_id() {
        let max_node = "a".repeat(MAX_NODE_ID_LEN);
        let hlc = Hlc::from_string(&format!("1000:0:{max_node}")).unwrap();
        assert_eq!(hlc.node_id, max_node);
    }

    #[test]
    fn to_string_format() {
        let hlc = Hlc::new(1710500000000, 3, "abc123");
        assert_eq!(hlc.to_string(), "1710500000000:3:abc123");
    }

    #[test]
    fn roundtrip_parse_display() {
        let original = "1710500000000:42:a1b2c3d4e5f6";
        let hlc = Hlc::from_string(original).unwrap();
        assert_eq!(hlc.to_string(), original);
    }

    #[test]
    fn now_creates_current_timestamp() {
        let hlc = Hlc::now("testnode", None);
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
        // Should be within 100ms of now
        assert!((hlc.timestamp - now_ms).abs() < 100);
        assert_eq!(hlc.counter, 0);
        assert_eq!(hlc.node_id, "testnode");
    }

    #[test]
    fn now_increments_counter_when_clock_not_advanced() {
        // Create a "last known" HLC far in the future so wall clock won't exceed it
        let future_ts = Hlc::now_ms() + 100_000;
        let last = Hlc::new(future_ts, 7, "testnode");
        let hlc = Hlc::now("testnode", Some(&last));
        assert_eq!(hlc.timestamp, future_ts);
        assert_eq!(hlc.counter, 8);
    }

    #[test]
    fn now_resets_counter_when_clock_advances() {
        // Create a "last known" HLC in the distant past
        let last = Hlc::new(1000, 99, "testnode");
        let hlc = Hlc::now("testnode", Some(&last));
        assert!(hlc.timestamp > last.timestamp);
        assert_eq!(hlc.counter, 0);
    }

    #[test]
    fn merge_wall_clock_wins() {
        // Both local and remote are in the past — wall clock should dominate
        let local = Hlc::new(1000, 5, "local");
        let remote = Hlc::new(2000, 3, "remote");
        let merged = local.merge(&remote, "local");
        // Wall clock (now) should be > 2000, so counter resets to 0
        assert!(merged.timestamp > 2000);
        assert_eq!(merged.counter, 0);
        assert_eq!(merged.node_id, "local");
    }

    #[test]
    fn merge_local_ts_equals_remote_ts_and_both_dominate_wall() {
        // Set both timestamps far in the future to dominate wall clock
        let future_ts = Hlc::now_ms() + 100_000;
        let local = Hlc::new(future_ts, 3, "local");
        let remote = Hlc::new(future_ts, 7, "remote");
        let merged = local.merge(&remote, "local");
        assert_eq!(merged.timestamp, future_ts);
        assert_eq!(merged.counter, 8); // max(3, 7) + 1
        assert_eq!(merged.node_id, "local");
    }

    #[test]
    fn merge_local_ts_dominates() {
        let future_ts = Hlc::now_ms() + 100_000;
        let local = Hlc::new(future_ts, 5, "local");
        let remote = Hlc::new(future_ts - 50_000, 10, "remote");
        let merged = local.merge(&remote, "local");
        assert_eq!(merged.timestamp, future_ts);
        assert_eq!(merged.counter, 6); // local.counter + 1
    }

    #[test]
    fn merge_remote_ts_dominates() {
        let future_ts = Hlc::now_ms() + 100_000;
        let local = Hlc::new(future_ts - 50_000, 10, "local");
        let remote = Hlc::new(future_ts, 5, "remote");
        let merged = local.merge(&remote, "local");
        assert_eq!(merged.timestamp, future_ts);
        assert_eq!(merged.counter, 6); // remote.counter + 1
    }

    #[test]
    fn comparison_by_timestamp() {
        let a = Hlc::new(1000, 0, "node");
        let b = Hlc::new(2000, 0, "node");
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn comparison_by_counter() {
        let a = Hlc::new(1000, 1, "node");
        let b = Hlc::new(1000, 2, "node");
        assert!(a < b);
    }

    #[test]
    fn comparison_by_node_id() {
        let a = Hlc::new(1000, 1, "aaa");
        let b = Hlc::new(1000, 1, "bbb");
        assert!(a < b);
    }

    #[test]
    fn equality() {
        let a = Hlc::new(1000, 1, "node");
        let b = Hlc::new(1000, 1, "node");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_timestamp() {
        let a = Hlc::new(1000, 1, "node");
        let b = Hlc::new(1001, 1, "node");
        assert_ne!(a, b);
    }

    #[test]
    fn drift_detection_within_tolerance() {
        let hlc = Hlc::now("node", None);
        assert!(!hlc.is_drift_exceeded(60_000));
    }

    #[test]
    fn drift_detection_exceeds_tolerance() {
        let far_future = Hlc::now_ms() + 120_000;
        let hlc = Hlc::new(far_future, 0, "node");
        assert!(hlc.is_drift_exceeded(60_000));
    }

    #[test]
    fn drift_detection_past_always_accepted() {
        // Past timestamps are always valid in a CRDT — old data is normal
        let far_past = Hlc::now_ms() - 120_000;
        let hlc = Hlc::new(far_past, 0, "node");
        assert!(!hlc.is_drift_exceeded(60_000));
    }

    #[test]
    fn hash_consistency() {
        use std::collections::HashSet;
        let a = Hlc::new(1000, 1, "node");
        let b = Hlc::new(1000, 1, "node");
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn parse_many_and_max_handles_counter_overflow() {
        // Regression for the `:9` vs `:10` bug: a SQL MAX would return
        // `1700000000:9:nodeA` (because `'9' > '1'` lexicographically).
        // parse_many_and_max must return the true HLC max.
        let values = vec!["1700000000:9:nodeA".to_string(), "1700000000:10:nodeA".to_string()];
        let max = Hlc::parse_many_and_max(&values).unwrap().expect("non-empty input");
        assert_eq!(max.counter, 10);
        assert_eq!(max.timestamp, 1700000000);
        assert_eq!(max.node_id, "nodeA");
    }

    #[test]
    fn parse_many_and_max_empty_returns_none() {
        let values: Vec<String> = Vec::new();
        assert!(Hlc::parse_many_and_max(&values).unwrap().is_none());
    }

    #[test]
    fn parse_many_and_max_prefers_higher_timestamp() {
        let values = vec!["1700000000:99:nodeA".to_string(), "1700000001:0:nodeA".to_string()];
        let max = Hlc::parse_many_and_max(&values).unwrap().unwrap();
        assert_eq!(max.timestamp, 1700000001);
        assert_eq!(max.counter, 0);
    }

    #[test]
    fn parse_many_and_max_breaks_ties_by_node_id() {
        let values = vec!["1700000000:5:aaa".to_string(), "1700000000:5:zzz".to_string()];
        let max = Hlc::parse_many_and_max(&values).unwrap().unwrap();
        assert_eq!(max.node_id, "zzz");
    }

    #[test]
    fn parse_many_and_max_propagates_parse_error() {
        let values = vec!["not-a-valid-hlc".to_string()];
        assert!(Hlc::parse_many_and_max(&values).is_err());
    }

    #[test]
    fn zero_constructor() {
        let hlc = Hlc::zero("mynode");
        assert_eq!(hlc.timestamp, 0);
        assert_eq!(hlc.counter, 0);
        assert_eq!(hlc.node_id, "mynode");
    }
}
