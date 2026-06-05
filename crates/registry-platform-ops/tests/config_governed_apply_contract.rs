use registry_platform_ops::{
    AntiRollbackKey, AntiRollbackProposal, AntiRollbackRecord, AntiRollbackStoreError,
    ApplyReportResult, BreakGlassApproval, BreakGlassRateLimit, FileAntiRollbackStore,
    PostureApplyResult,
};

fn key() -> AntiRollbackKey {
    AntiRollbackKey {
        product: "registry-relay".to_string(),
        instance_id: "relay-a".to_string(),
        environment: "production".to_string(),
        stream_id: "national-config".to_string(),
    }
}

fn hash(label: &str) -> String {
    format!(
        "sha256:{:0<64}",
        label
            .as_bytes()
            .iter()
            .fold(String::new(), |mut output, byte| {
                output.push_str(&format!("{byte:02x}"));
                output
            })
    )
}

fn record(sequence: u64, config_hash: &str) -> AntiRollbackRecord {
    AntiRollbackRecord {
        key: key(),
        last_sequence: sequence,
        last_config_hash: config_hash.to_string(),
        root_version: Some(3),
        break_glass: Default::default(),
    }
}

fn approval(expires_at_unix_seconds: u64) -> BreakGlassApproval {
    BreakGlassApproval {
        approved_by: "ops@example.test".to_string(),
        reason: "recover from bad live config".to_string(),
        approval_reference: "INC-4242".to_string(),
        emergency_change_class: "emergency_break_glass".to_string(),
        expires_at_unix_seconds,
        rate_limit_identity: "registry-relay/relay-a/production/national-config".to_string(),
    }
}

fn rate_limit() -> BreakGlassRateLimit {
    BreakGlassRateLimit {
        max_accepted: 1,
        window_seconds: 3600,
    }
}

#[test]
fn apply_report_result_projects_to_posture_vocabulary() {
    assert_eq!(
        ApplyReportResult::Verified.as_posture_result(),
        PostureApplyResult::NotApplied
    );
    assert_eq!(
        ApplyReportResult::Applied.as_posture_result(),
        PostureApplyResult::Accepted
    );
    assert_eq!(
        ApplyReportResult::RejectedRollback.as_posture_result(),
        PostureApplyResult::Rejected
    );
    assert_eq!(
        ApplyReportResult::InternalError.as_posture_result(),
        PostureApplyResult::Failed
    );

    assert_eq!(PostureApplyResult::Accepted.as_str(), "accepted");
    assert_eq!(PostureApplyResult::Rejected.as_str(), "rejected");
    assert_eq!(PostureApplyResult::Failed.as_str(), "failed");
    assert_eq!(PostureApplyResult::NotApplied.as_str(), "not_applied");
}

#[test]
fn antirollback_missing_state_fails_closed_for_apply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));

    let err = store
        .load(&key())
        .expect_err("missing state is not accepted");
    assert_eq!(err, AntiRollbackStoreError::MissingState);
}

#[test]
fn antirollback_state_survives_new_store_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config-antirollback.json");
    let first = FileAntiRollbackStore::new(&path);
    first
        .initialize(record(41, &hash("old")))
        .expect("initial state writes");

    let second = FileAntiRollbackStore::new(&path);
    assert_eq!(
        second.load(&key()).expect("state loads after restart"),
        record(41, &hash("old"))
    );
}

#[test]
fn antirollback_rejects_non_monotonic_sequence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 42,
                previous_config_hash: Some(hash("current")),
                config_hash: hash("next"),
                root_version: Some(3),
                break_glass: None,
                break_glass_rate_limit: None,
            },
        )
        .expect_err("same sequence is rollback");

    assert_eq!(err, AntiRollbackStoreError::NonMonotonicSequence);
}

#[test]
fn antirollback_rejects_previous_hash_mismatch_without_break_glass() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("next"),
                root_version: Some(3),
                break_glass: None,
                break_glass_rate_limit: None,
            },
        )
        .expect_err("previous hash mismatch is rejected");

    assert_eq!(err, AntiRollbackStoreError::PreviousConfigHashMismatch);
}

#[test]
fn antirollback_rejects_root_version_rollback() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("current")),
                config_hash: hash("next"),
                root_version: Some(2),
                break_glass: None,
                break_glass_rate_limit: None,
            },
        )
        .expect_err("root version rollback is rejected");

    assert_eq!(err, AntiRollbackStoreError::RootVersionRollback);
    assert_eq!(
        store.load(&key()).expect("state did not advance"),
        record(42, &hash("current"))
    );
}

#[test]
fn break_glass_requires_local_approval_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: None,
                break_glass_rate_limit: Some(rate_limit()),
            },
        )
        .expect_err("break-glass requires local approval policy");

    assert_eq!(err, AntiRollbackStoreError::PreviousConfigHashMismatch);
    assert_eq!(
        store.load(&key()).expect("state did not advance"),
        record(42, &hash("current"))
    );
}

#[test]
fn break_glass_waives_previous_hash_only_with_valid_approval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let accepted = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(2_000)),
                break_glass_rate_limit: Some(rate_limit()),
            },
            1_000,
        )
        .expect("approved break-glass can waive previous hash");

    assert_eq!(accepted.last_sequence, 43);
    assert_eq!(accepted.last_config_hash, hash("recovery"));
    assert_eq!(accepted.root_version, Some(4));
    assert_eq!(accepted.break_glass.accepted.len(), 1);
    assert_eq!(accepted.break_glass.accepted[0].sequence, 43);
    assert_eq!(
        accepted.break_glass.accepted[0].approval_reference,
        "INC-4242"
    );
}

#[test]
fn break_glass_never_waives_monotonic_sequence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let err = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 42,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(2_000)),
                break_glass_rate_limit: Some(rate_limit()),
            },
            1_000,
        )
        .expect_err("sequence rollback is rejected before approval can waive hash");

    assert_eq!(err, AntiRollbackStoreError::NonMonotonicSequence);
    assert_eq!(
        store.load(&key()).expect("state did not advance"),
        record(42, &hash("current"))
    );
}

#[test]
fn break_glass_rejects_expired_or_incomplete_approval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    let expired = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(999)),
                break_glass_rate_limit: Some(rate_limit()),
            },
            1_000,
        )
        .expect_err("expired approval is rejected");
    assert_eq!(expired, AntiRollbackStoreError::BreakGlassApprovalExpired);

    let mut incomplete = approval(2_000);
    incomplete.reason.clear();
    let invalid = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(incomplete),
                break_glass_rate_limit: Some(rate_limit()),
            },
            1_000,
        )
        .expect_err("reason is required");
    assert_eq!(
        invalid,
        AntiRollbackStoreError::InvalidBreakGlassApproval("reason")
    );

    assert_eq!(
        store.load(&key()).expect("state did not advance"),
        record(42, &hash("current"))
    );
}

#[test]
fn break_glass_is_rate_limited_in_rolling_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileAntiRollbackStore::new(dir.path().join("config-antirollback.json"));
    store
        .initialize(record(42, &hash("current")))
        .expect("initial state writes");

    store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 43,
                previous_config_hash: Some(hash("other")),
                config_hash: hash("recovery"),
                root_version: Some(4),
                break_glass: Some(approval(2_000)),
                break_glass_rate_limit: Some(rate_limit()),
            },
            1_000,
        )
        .expect("first break-glass is accepted");

    let limited = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 44,
                previous_config_hash: Some(hash("wrong-again")),
                config_hash: hash("recovery2"),
                root_version: Some(4),
                break_glass: Some(approval(2_100)),
                break_glass_rate_limit: Some(rate_limit()),
            },
            1_100,
        )
        .expect_err("second break-glass in same window is rejected");
    assert_eq!(limited, AntiRollbackStoreError::BreakGlassRateLimited);

    let accepted_after_window = store
        .accept_at(
            &key(),
            AntiRollbackProposal {
                sequence: 44,
                previous_config_hash: Some(hash("wrong-again")),
                config_hash: hash("recovery2"),
                root_version: Some(4),
                break_glass: Some(approval(6_000)),
                break_glass_rate_limit: Some(rate_limit()),
            },
            5_000,
        )
        .expect("break-glass outside the rolling window is accepted");
    assert_eq!(accepted_after_window.last_sequence, 44);
}
