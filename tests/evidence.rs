use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use cheirismos::domain::{ArtifactDigest, AttemptId};
use cheirismos::evidence::{ArtifactStore, EvidenceError, EvidenceSource};

fn attempt(value: impl Into<String>) -> Result<AttemptId, cheirismos::domain::DomainError> {
    AttemptId::try_from(value.into())
}

fn reference_path(root: &Path, digest: &ArtifactDigest, id: &str) -> PathBuf {
    let text = digest.as_str();
    root.join("references")
        .join("sha256")
        .join(&text[..2])
        .join(&text[2..])
        .join("attempt")
        .join(id)
}

fn mode(path: &Path) -> Result<u32, std::io::Error> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

#[test]
fn publication_uses_private_modes_and_repairs_existing_files()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let root = parent.path().join("evidence");
    let store = ArtifactStore::open(&root)?;
    let source = EvidenceSource::Attempt(attempt("attempt-private")?);
    let digest = store.publish(b"private evidence", source.clone())?;
    let artifact = store.path_for(&digest);
    let marker = reference_path(&root, &digest, "attempt-private");

    let text = digest.as_str();
    let directories = [
        root.clone(),
        root.join("sha256"),
        root.join("sha256").join(&text[..2]),
        root.join("references"),
        root.join("references").join("sha256"),
        root.join("references").join("sha256").join(&text[..2]),
        root.join("references")
            .join("sha256")
            .join(&text[..2])
            .join(&text[2..]),
        root.join("references")
            .join("sha256")
            .join(&text[..2])
            .join(&text[2..])
            .join("attempt"),
    ];
    for directory in directories {
        assert_eq!(mode(&directory)?, 0o700, "{}", directory.display());
    }
    assert_eq!(mode(&artifact)?, 0o600);
    assert_eq!(mode(&marker)?, 0o600);

    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644))?;
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o644))?;
    assert_eq!(store.publish(b"private evidence", source)?, digest);
    assert_eq!(mode(&artifact)?, 0o600);
    assert_eq!(mode(&marker)?, 0o600);
    Ok(())
}

#[test]
fn opening_rejects_symlink_and_non_directory_components() -> Result<(), Box<dyn std::error::Error>>
{
    let parent = tempfile::tempdir()?;
    let actual = parent.path().join("actual");
    fs::create_dir(&actual)?;
    let linked = parent.path().join("linked");
    symlink(&actual, &linked)?;
    assert!(ArtifactStore::open(linked.join("evidence")).is_err());
    assert!(!actual.join("evidence").exists());

    let file = parent.path().join("file");
    fs::write(&file, b"not a directory")?;
    assert!(ArtifactStore::open(file.join("evidence")).is_err());
    Ok(())
}

#[test]
fn publication_rejects_symlink_and_non_directory_cas_traps()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let first_root = parent.path().join("symlink-store");
    let first = ArtifactStore::open(&first_root)?;
    let bytes = b"trapped evidence";
    let digest = ArtifactDigest::sha256(bytes);
    let artifact = first.path_for(&digest);
    fs::create_dir_all(artifact.parent().ok_or("artifact has no parent")?)?;
    let outside = parent.path().join("outside");
    fs::write(&outside, b"outside")?;
    symlink(&outside, &artifact)?;
    assert!(
        first
            .publish(bytes, EvidenceSource::Attempt(attempt("attempt-symlink")?))
            .is_err()
    );
    assert_eq!(fs::read(&outside)?, b"outside");
    assert!(!reference_path(&first_root, &digest, "attempt-symlink").exists());

    let second_root = parent.path().join("file-store");
    let second = ArtifactStore::open(&second_root)?;
    fs::write(second_root.join("sha256"), b"not a directory")?;
    assert!(
        second
            .publish(
                b"other evidence",
                EvidenceSource::Attempt(attempt("attempt-file")?)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn source_verification_rejects_symlinked_ancestors_and_invalid_markers()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let root = parent.path().join("evidence");
    let store = ArtifactStore::open(&root)?;
    let first_source = EvidenceSource::Attempt(attempt("attempt-first")?);
    let digest = store.publish(b"source evidence", first_source.clone())?;

    let references = root.join("references");
    let saved_references = root.join("saved-references");
    fs::rename(&references, &saved_references)?;
    symlink(&saved_references, &references)?;
    assert!(store.verify_source(&digest, &first_source).is_err());
    fs::remove_file(&references)?;
    fs::rename(&saved_references, &references)?;

    let second_id = "attempt-second";
    let second_marker = reference_path(&root, &digest, second_id);
    symlink(parent.path().join("missing"), &second_marker)?;
    assert!(
        store
            .publish(
                b"source evidence",
                EvidenceSource::Attempt(attempt(second_id)?)
            )
            .is_err()
    );
    fs::remove_file(&second_marker)?;
    fs::create_dir(&second_marker)?;
    assert!(
        store
            .publish(
                b"source evidence",
                EvidenceSource::Attempt(attempt(second_id)?)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn digest_mismatch_cannot_acquire_new_provenance() -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let root = parent.path().join("evidence");
    let store = ArtifactStore::open(&root)?;
    let digest = store.publish(
        b"original evidence",
        EvidenceSource::Attempt(attempt("attempt-original")?),
    )?;
    fs::write(store.path_for(&digest), b"tampered evidence")?;

    assert!(
        store
            .publish(
                b"original evidence",
                EvidenceSource::Attempt(attempt("attempt-laundered")?)
            )
            .is_err()
    );
    assert!(!reference_path(&root, &digest, "attempt-laundered").exists());
    Ok(())
}

#[test]
fn concurrent_duplicate_publishers_preserve_each_provenance_marker()
-> Result<(), Box<dyn std::error::Error>> {
    const PUBLISHERS: usize = 8;
    let parent = tempfile::tempdir()?;
    let store = Arc::new(ArtifactStore::open(parent.path().join("evidence"))?);
    let barrier = Arc::new(Barrier::new(PUBLISHERS));
    let mut publishers = Vec::new();
    for index in 0..PUBLISHERS {
        let store = store.clone();
        let barrier = barrier.clone();
        publishers.push(std::thread::spawn(
            move || -> Result<(ArtifactDigest, EvidenceSource), EvidenceError> {
                let source = EvidenceSource::Attempt(
                    attempt(format!("attempt-concurrent-{index}"))
                        .map_err(|source| EvidenceError::Domain { source })?,
                );
                barrier.wait();
                let digest = store.publish(b"concurrent evidence", source.clone())?;
                Ok((digest, source))
            },
        ));
    }

    let mut expected_digest = None;
    for publisher in publishers {
        let (digest, source) = publisher.join().map_err(|_| "publisher panicked")??;
        if let Some(expected) = &expected_digest {
            assert_eq!(expected, &digest);
        } else {
            expected_digest = Some(digest.clone());
        }
        assert_eq!(
            store.verify_source(&digest, &source)?.as_bytes(),
            b"concurrent evidence"
        );
    }
    Ok(())
}

#[test]
fn stale_temporary_names_do_not_block_publication() -> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let root = parent.path().join("evidence");
    let store = ArtifactStore::open(&root)?;
    let bytes = b"evidence after stale temporary files";
    let digest = ArtifactDigest::sha256(bytes);
    let artifact = store.path_for(&digest);
    let artifact_directory = artifact.parent().ok_or("artifact has no parent")?;
    fs::create_dir_all(artifact_directory)?;
    for sequence in 0..128 {
        fs::write(
            artifact_directory.join(format!(
                ".{}.{}.{}.partial",
                digest.as_str(),
                std::process::id(),
                sequence
            )),
            b"stale",
        )?;
    }

    assert_eq!(
        store.publish(
            bytes,
            EvidenceSource::Attempt(attempt("attempt-after-stale")?)
        )?,
        digest
    );
    assert_eq!(store.read(&digest)?.as_bytes(), bytes);
    Ok(())
}

#[test]
fn retry_after_provenance_failure_reuses_verified_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = tempfile::tempdir()?;
    let root = parent.path().join("evidence");
    let store = ArtifactStore::open(&root)?;
    let source = EvidenceSource::Attempt(attempt("attempt-retry")?);
    let digest = ArtifactDigest::sha256(b"retry evidence");
    fs::write(root.join("references"), b"block provenance")?;

    assert!(store.publish(b"retry evidence", source.clone()).is_err());
    assert_eq!(store.read(&digest)?.as_bytes(), b"retry evidence");
    fs::remove_file(root.join("references"))?;

    assert_eq!(store.publish(b"retry evidence", source.clone())?, digest);
    assert_eq!(
        store.verify_source(&digest, &source)?.as_bytes(),
        b"retry evidence"
    );
    Ok(())
}
