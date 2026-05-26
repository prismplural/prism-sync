use prism_sync_core::storage::RusqliteSyncStorage;
use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn applied_ops_sync_seq_index_present() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("test.db");

    let conn = Connection::open(&db_path).unwrap();
    let _storage = RusqliteSyncStorage::new(conn).unwrap();

    let conn = Connection::open(&db_path).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type='index' AND name='idx_applied_ops_sync_seq'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "V7 must create idx_applied_ops_sync_seq");

    // Column order matters for the prune-window query plan.
    let info: Vec<(i64, String)> = conn
        .prepare("PRAGMA index_info('idx_applied_ops_sync_seq')")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(2)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(info.len(), 2, "index should be on 2 columns");
    assert_eq!(info[0].1, "sync_id", "first column should be sync_id");
    assert_eq!(info[1].1, "server_seq", "second column should be server_seq");
}

#[test]
fn prune_count_query_uses_idx_applied_ops_sync_seq() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("test.db");
    let conn = Connection::open(&db_path).unwrap();
    let _storage = RusqliteSyncStorage::new(conn).unwrap();

    let conn = Connection::open(&db_path).unwrap();
    // EXPLAIN QUERY PLAN row layout is (id, parent, notused, detail);
    // matching the index name in `detail` is brittle to SQLite output.
    let detail: String = conn
        .query_row(
            "EXPLAIN QUERY PLAN \
             SELECT COUNT(*) FROM applied_ops WHERE sync_id = ? AND server_seq < ?",
            rusqlite::params!["sync-x", 1000i64],
            |r| r.get(3),
        )
        .unwrap();

    assert!(
        detail.contains("idx_applied_ops_sync_seq"),
        "expected query plan to use idx_applied_ops_sync_seq, got: {detail}"
    );
}
