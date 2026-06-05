use std::path::{Path, PathBuf};

use chrono::{TimeDelta, Utc};
use registry_platform_config::{
    sha256_uri, ConfigVerificationError, LocalTufRepositoryInput, TufConfigVerifier,
    VerificationContext,
};
use tempfile::TempDir;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};

const TUF_REFERENCE_TARGETS_SIGNER_KID: &str =
    "65171251a9aff5a8b3143a813481cb07f6e0de4eb197c767837fe4491b739093";

fn tough_fixture_dir(name: &str) -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .expect("CARGO_HOME or HOME is set");
    let src_root = cargo_home.join("registry/src");
    let registry = std::fs::read_dir(&src_root)
        .expect("cargo registry src exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("tough-0.22.0/tests/data").is_dir())
        .expect("tough-0.22.0 source fixture directory exists");
    registry.join("tough-0.22.0/tests/data").join(name)
}

fn input_for_fixture(
    base: &Path,
    datastore: &TempDir,
    target_name: &str,
) -> LocalTufRepositoryInput {
    LocalTufRepositoryInput {
        root_path: base.join("metadata").join("1.root.json"),
        metadata_dir: base.join("metadata"),
        targets_dir: base.join("targets"),
        datastore_dir: datastore.path().to_path_buf(),
        target_name: target_name.to_string(),
    }
}

async fn generated_repository_input(
    repo: &TempDir,
    datastore: &TempDir,
    target_name: &str,
    version: u64,
) -> LocalTufRepositoryInput {
    let data = tough_fixture_dir("");
    let root_path = data.join("simple-rsa").join("root.json");
    let key_path = data.join("snakeoil.pem");
    let target_path = data.join("targets").join(target_name);
    let metadata_dir = repo.path().join("metadata");
    let targets_dir = repo.path().join("targets");
    let expiry = Utc::now()
        .checked_add_signed(TimeDelta::try_days(30).expect("duration"))
        .expect("future expiration");
    let version = std::num::NonZeroU64::new(version).expect("non-zero version");

    let mut editor = RepositoryEditor::new(&root_path)
        .await
        .expect("editor loads fixture root");
    editor.targets_expires(expiry).expect("targets expiration");
    editor.targets_version(version).expect("targets version");
    editor.snapshot_expires(expiry);
    editor.snapshot_version(version);
    editor.timestamp_expires(expiry);
    editor.timestamp_version(version);
    editor
        .add_target_paths(vec![target_path])
        .await
        .expect("target path");
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource { path: key_path })];
    let signed = editor.sign(&keys).await.expect("repository signs");
    signed.write(&metadata_dir).await.expect("metadata writes");
    signed
        .link_targets(data.join("targets"), &targets_dir, PathExists::Skip)
        .await
        .expect("targets link");

    LocalTufRepositoryInput {
        root_path,
        metadata_dir,
        targets_dir,
        datastore_dir: datastore.path().to_path_buf(),
        target_name: target_name.to_string(),
    }
}

#[tokio::test]
async fn verifies_local_tuf_target_without_network_and_reports_versions() {
    let base = tough_fixture_dir("tuf-reference-impl");
    let datastore = TempDir::new().expect("datastore tempdir");
    let input = input_for_fixture(&base, &datastore, "file1.txt");

    let target = TufConfigVerifier::verify_local_target(&input)
        .await
        .expect("tough verifies local repository target");

    assert_eq!(target.target_bytes, b"This is an example target file.");
    assert_eq!(target.target_name, "file1.txt");
    assert!(target.root_version >= 1);
    assert!(target.targets_version >= 1);
    assert!(target.snapshot_version >= 1);
    assert!(target.timestamp_version >= 1);
    assert_eq!(
        target.root_sha256,
        sha256_uri(
            &std::fs::read(base.join("metadata").join("1.root.json"))
                .expect("trusted root fixture reads")
        )
    );
    assert_eq!(
        target.signer_kids,
        vec![TUF_REFERENCE_TARGETS_SIGNER_KID.to_string()]
    );
    assert_eq!(target.custom_metadata["file_permissions"], "0644");
}

#[tokio::test]
async fn expired_timestamp_fails_closed_with_safe_expiration_enforcement() {
    let base = tough_fixture_dir("expired-repository");
    let datastore = TempDir::new().expect("datastore tempdir");
    let input = input_for_fixture(&base, &datastore, "file1.txt");

    let error = TufConfigVerifier::verify_local_target(&input)
        .await
        .expect_err("expired timestamp must be rejected");

    assert!(matches!(error, ConfigVerificationError::Tuf(_)));
    assert!(error.to_string().contains("timestamp"));
}

#[tokio::test]
async fn rollback_rejected_with_same_tough_datastore() {
    let datastore = TempDir::new().expect("datastore tempdir");
    let newer_repo = TempDir::new().expect("newer repo tempdir");
    let older_repo = TempDir::new().expect("older repo tempdir");
    let target_name = "file4.txt";
    let newer_input = generated_repository_input(&newer_repo, &datastore, target_name, 2).await;
    let older_input = generated_repository_input(&older_repo, &datastore, target_name, 1).await;

    let newer_target = TufConfigVerifier::verify_local_target(&newer_input)
        .await
        .expect("newer repository verifies and seeds datastore");

    assert_eq!(newer_target.timestamp_version, 2);
    assert_eq!(newer_target.snapshot_version, 2);
    assert!(datastore.path().join("latest_known_time.json").is_file());
    assert!(datastore.path().join("timestamp.json").is_file());
    assert!(datastore.path().join("snapshot.json").is_file());

    let error = TufConfigVerifier::verify_local_target(&older_input)
        .await
        .expect_err("older signed metadata is rejected by tough rollback checks");

    assert!(matches!(error, ConfigVerificationError::Tuf(_)));
    assert!(
        error.to_string().contains("older")
            || error.to_string().contains("rollback")
            || error.to_string().contains("version")
    );
}

#[tokio::test]
async fn config_target_verification_rejects_missing_registry_custom_metadata_after_tuf() {
    let base = tough_fixture_dir("tuf-reference-impl");
    let datastore = TempDir::new().expect("datastore tempdir");
    let input = input_for_fixture(&base, &datastore, "file1.txt");
    let context = VerificationContext {
        product: "registry-relay".to_string(),
        instance_id: "relay-a".to_string(),
        environment: "production".to_string(),
    };

    let error = TufConfigVerifier::verify_config_target(&input, &context)
        .await
        .expect_err("non-Registry target metadata is rejected");

    assert!(matches!(
        error,
        ConfigVerificationError::InvalidTargetMetadata(_)
    ));
}
