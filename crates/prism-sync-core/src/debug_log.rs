use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;

use chrono::{DateTime, Utc};

/// A single debug log entry.
#[derive(Debug, Clone)]
pub struct DebugLogEntry {
    pub timestamp: DateTime<Utc>,
    pub category: String,
    pub message: String,
    pub details: serde_json::Value,
}

impl fmt::Display for DebugLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] [{}] {}", self.timestamp.to_rfc3339(), self.category, self.message)?;
        if self.details != serde_json::Value::Null
            && self.details != serde_json::Value::Object(serde_json::Map::new())
        {
            write!(f, "\n{}", serde_json::to_string_pretty(&self.details).unwrap_or_default())?;
        }
        Ok(())
    }
}

/// In-memory circular buffer debug log for sync troubleshooting.
///
/// Thread-safe via internal Mutex. Max 500 entries by default.
///
/// Categories: data, sync, runtime, snapshot, ws, pairing
///
/// Ported from Dart `lib/core/sync/sync_debug_log.dart`.
pub struct SyncDebugLog {
    entries: Mutex<VecDeque<DebugLogEntry>>,
    max_entries: usize,
}

impl SyncDebugLog {
    /// Create a new debug log with the given maximum entry count.
    pub fn new(max_entries: usize) -> Self {
        Self { entries: Mutex::new(VecDeque::with_capacity(max_entries)), max_entries }
    }

    /// Create a debug log with the default max (500 entries).
    pub fn default_max() -> Self {
        Self::new(500)
    }

    /// Add a log entry with details.
    ///
    /// If the buffer is full, the oldest entry is evicted.
    pub fn log(
        &self,
        category: impl Into<String>,
        message: impl Into<String>,
        details: serde_json::Value,
    ) {
        let entry = DebugLogEntry {
            timestamp: Utc::now(),
            category: category.into(),
            message: message.into(),
            details,
        };

        let mut entries = self.entries.lock().expect("debug log mutex poisoned");
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Log with no details.
    pub fn log_simple(&self, category: impl Into<String>, message: impl Into<String>) {
        self.log(category, message, serde_json::Value::Null);
    }

    /// Get all entries (oldest first).
    pub fn entries(&self) -> Vec<DebugLogEntry> {
        let entries = self.entries.lock().expect("debug log mutex poisoned");
        entries.iter().cloned().collect()
    }

    /// Get entry count.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("debug log mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.entries.lock().expect("debug log mutex poisoned").clear();
    }

    /// Export all entries as a human-readable text string.
    ///
    /// Format matches the Dart implementation for consistency:
    /// ```text
    /// [2026-03-15T12:00:00+00:00] [sync] Pull started
    /// {
    ///   "sinceSeq": 0
    /// }
    /// ```
    pub fn export_text(&self) -> String {
        let entries = self.entries.lock().expect("debug log mutex poisoned");
        let mut output = String::new();
        for entry in entries.iter() {
            output.push_str(&entry.to_string());
            output.push('\n');
            output.push('\n');
        }
        output.trim_end().to_string()
    }
}

impl Default for SyncDebugLog {
    fn default() -> Self {
        Self::default_max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_and_retrieve() {
        let log = SyncDebugLog::new(10);
        log.log_simple("sync", "test message");
        assert_eq!(log.len(), 1);
        let entries = log.entries();
        assert_eq!(entries[0].category, "sync");
        assert_eq!(entries[0].message, "test message");
    }

    #[test]
    fn circular_buffer_evicts_oldest() {
        let log = SyncDebugLog::new(3);
        log.log_simple("sync", "msg1");
        log.log_simple("sync", "msg2");
        log.log_simple("sync", "msg3");
        log.log_simple("sync", "msg4");
        assert_eq!(log.len(), 3);
        let entries = log.entries();
        assert_eq!(entries[0].message, "msg2");
        assert_eq!(entries[2].message, "msg4");
    }

    #[test]
    fn clear_removes_all() {
        let log = SyncDebugLog::new(10);
        log.log_simple("sync", "msg1");
        log.log_simple("sync", "msg2");
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn export_text_format() {
        let log = SyncDebugLog::new(10);
        log.log("sync", "Pull started", serde_json::json!({"sinceSeq": 0}));
        let text = log.export_text();
        assert!(text.contains("[sync] Pull started"));
        assert!(text.contains("\"sinceSeq\": 0"));
    }

    #[test]
    fn log_with_details() {
        let log = SyncDebugLog::new(10);
        log.log(
            "data",
            "Applied remote batch",
            serde_json::json!({
                "syncId": "sync-1",
                "serverSeq": 42,
                "opCount": 5
            }),
        );
        let entries = log.entries();
        assert_eq!(entries[0].details["opCount"], 5);
    }

    #[test]
    fn default_max_is_500() {
        let log = SyncDebugLog::default_max();
        for i in 0..600 {
            log.log_simple("sync", format!("msg{i}"));
        }
        assert_eq!(log.len(), 500);
    }
}
