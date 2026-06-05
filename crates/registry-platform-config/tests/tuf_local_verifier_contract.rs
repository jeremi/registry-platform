use std::path::{Path, PathBuf};

use std::collections::HashMap;

use chrono::{TimeDelta, Utc};
use registry_platform_config::{
    sha256_uri, ConfigVerificationError, LocalTufRepositoryInput, RemoteTufRepositoryInput,
    TufConfigVerifier, VerificationContext,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::Target;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

async fn serve_tuf_reference_fixture() -> MockServer {
    let server = MockServer::start().await;
    let base = tough_fixture_dir("tuf-reference-impl");
    for relative in [
        "metadata/timestamp.json",
        "metadata/snapshot.json",
        "metadata/targets.json",
        "metadata/role1.json",
        "metadata/role2.json",
        "targets/file1.txt",
        "targets/file2.txt",
    ] {
        let bytes = std::fs::read(base.join(relative)).expect("fixture file reads");
        Mock::given(method("GET"))
            .and(path(format!("/{relative}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/metadata/2.root.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    server
}

async fn mount_directory_files(server: &MockServer, url_prefix: &str, dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("directory reads") {
        let entry = entry.expect("directory entry reads");
        let path_on_disk = entry.path();
        if !path_on_disk.is_file() {
            continue;
        }
        let filename = path_on_disk
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture filename is UTF-8");
        let url_path = format!("{url_prefix}/{filename}");
        Mock::given(method("GET"))
            .and(path(url_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(
                    std::fs::read(path_on_disk).expect("generated repo file reads"),
                ),
            )
            .mount(server)
            .await;
    }
}

async fn generated_repository_input(
    repo: &TempDir,
    datastore: &TempDir,
    target_name: &str,
    version: u64,
) -> LocalTufRepositoryInput {
    generated_repository_input_with_custom(repo, datastore, target_name, version, None).await
}

async fn generated_repository_input_with_custom(
    repo: &TempDir,
    datastore: &TempDir,
    target_name: &str,
    version: u64,
    custom: Option<Value>,
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
    if let Some(Value::Object(custom)) = custom {
        let mut target = Target::from_path(&target_path)
            .await
            .expect("target metadata builds");
        target.custom = custom.into_iter().collect::<HashMap<_, _>>();
        editor
            .add_target(target_name.to_string(), target)
            .expect("target metadata with custom");
    } else {
        editor
            .add_target_paths(vec![target_path])
            .await
            .expect("target path");
    }
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
async fn verifies_remote_tuf_target_through_guarded_dev_transport() {
    let server = serve_tuf_reference_fixture().await;
    let base = tough_fixture_dir("tuf-reference-impl");
    let datastore = TempDir::new().expect("datastore tempdir");
    let input = RemoteTufRepositoryInput {
        root_path: base.join("metadata").join("1.root.json"),
        metadata_base_url: format!("{}/metadata", server.uri()),
        targets_base_url: format!("{}/targets", server.uri()),
        datastore_dir: datastore.path().to_path_buf(),
        target_name: "file1.txt".to_string(),
        allow_dev_insecure_fetch_urls: true,
    };

    let target = TufConfigVerifier::verify_remote_target(&input)
        .await
        .expect("remote TUF target verifies through guarded transport");

    assert_eq!(target.target_bytes, b"This is an example target file.");
    assert_eq!(target.target_name, "file1.txt");
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
    assert!(datastore.path().join("latest_known_time.json").is_file());
}

#[tokio::test]
async fn remote_tuf_rejects_loopback_http_without_dev_opt_in_before_fetch() {
    let server = serve_tuf_reference_fixture().await;
    let base = tough_fixture_dir("tuf-reference-impl");
    let datastore = TempDir::new().expect("datastore tempdir");
    let input = RemoteTufRepositoryInput {
        root_path: base.join("metadata").join("1.root.json"),
        metadata_base_url: format!("{}/metadata", server.uri()),
        targets_base_url: format!("{}/targets", server.uri()),
        datastore_dir: datastore.path().to_path_buf(),
        target_name: "file1.txt".to_string(),
        allow_dev_insecure_fetch_urls: false,
    };

    let error = TufConfigVerifier::verify_remote_target(&input)
        .await
        .expect_err("strict transport rejects loopback http");

    assert!(matches!(error, ConfigVerificationError::UnsafeRemoteUrl(_)));
}

#[tokio::test]
async fn remote_config_target_verification_projects_registry_metadata() {
    let repo = TempDir::new().expect("repo tempdir");
    let datastore = TempDir::new().expect("datastore tempdir");
    let target_name = "file4.txt";
    let target = std::fs::read(tough_fixture_dir("").join("targets").join(target_name))
        .expect("target fixture reads");
    let custom = json!({
        "product": "registry-relay",
        "instance_id": "relay-a",
        "environment": "production",
        "stream_id": "default",
        "bundle_id": "bundle-43",
        "sequence": 43,
        "previous_config_hash": "sha256:old",
        "config_hash": sha256_uri(&target),
        "change_classes": ["public_metadata"],
        "signer_kids": ["metadata-only-kid"],
        "apply_policy": "hot_swap"
    });
    let local =
        generated_repository_input_with_custom(&repo, &datastore, target_name, 1, Some(custom))
            .await;
    let server = MockServer::start().await;
    mount_directory_files(&server, "/metadata", &local.metadata_dir).await;
    mount_directory_files(&server, "/targets", &local.targets_dir).await;
    Mock::given(method("GET"))
        .and(path("/metadata/2.root.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let remote_datastore = datastore.path().join("remote-datastore");
    std::fs::create_dir(&remote_datastore).expect("remote datastore dir exists");
    let remote = RemoteTufRepositoryInput {
        root_path: local.root_path,
        metadata_base_url: format!("{}/metadata", server.uri()),
        targets_base_url: format!("{}/targets", server.uri()),
        datastore_dir: remote_datastore,
        target_name: target_name.to_string(),
        allow_dev_insecure_fetch_urls: true,
    };
    let context = VerificationContext {
        product: "registry-relay".to_string(),
        instance_id: "relay-a".to_string(),
        environment: "production".to_string(),
    };

    let verified = TufConfigVerifier::verify_remote_config_target(&remote, &context)
        .await
        .expect("remote registry target verifies");

    assert_eq!(verified.metadata.bundle_id, "bundle-43");
    assert_eq!(verified.metadata.sequence, 43);
    assert_eq!(
        verified.metadata.signer_kids,
        verified.tuf.signer_kids.iter().cloned().collect()
    );
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

#[tokio::test]
async fn config_target_verification_uses_tuf_signer_kids_over_custom_metadata_claims() {
    let repo = TempDir::new().expect("repo tempdir");
    let datastore = TempDir::new().expect("datastore tempdir");
    let target_name = "file4.txt";
    let target = std::fs::read(tough_fixture_dir("").join("targets").join(target_name))
        .expect("target fixture reads");
    let custom = json!({
        "product": "registry-relay",
        "instance_id": "relay-a",
        "environment": "production",
        "stream_id": "default",
        "bundle_id": "bundle-43",
        "sequence": 43,
        "previous_config_hash": "sha256:old",
        "config_hash": sha256_uri(&target),
        "change_classes": ["public_metadata"],
        "signer_kids": ["metadata-only-kid"],
        "apply_policy": "restart_required"
    });
    let input =
        generated_repository_input_with_custom(&repo, &datastore, target_name, 1, Some(custom))
            .await;
    let context = VerificationContext {
        product: "registry-relay".to_string(),
        instance_id: "relay-a".to_string(),
        environment: "production".to_string(),
    };

    let verified = TufConfigVerifier::verify_config_target(&input, &context)
        .await
        .expect("valid registry custom metadata verifies");

    assert_eq!(
        verified.metadata.signer_kids,
        verified.tuf.signer_kids.iter().cloned().collect()
    );
    assert!(!verified.metadata.signer_kids.contains("metadata-only-kid"));
}
