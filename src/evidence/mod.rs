//! Content-addressed evidence publication with verified reads.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use snafu::Snafu;

use crate::domain::{ArtifactDigest, AttemptId, CaseId, DomainError, InstrumentId};

const DIRECTORY_MODE: Mode = Mode::RWXU;
const FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EvidenceError {
    #[snafu(display("evidence I/O failed: {source}"))]
    Io { source: std::io::Error },

    #[snafu(display("artifact digest does not match its content: {digest}"))]
    DigestMismatch { digest: ArtifactDigest },

    #[snafu(display("evidence root is not a directory: {}", path.display()))]
    InvalidRoot { path: PathBuf },

    #[snafu(display("evidence path has an invalid file type: {}", path.display()))]
    InvalidEntry { path: PathBuf },

    #[snafu(display("invalid evidence identifier: {source}"))]
    Domain { source: DomainError },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifact {
    digest: ArtifactDigest,
    bytes: Vec<u8>,
}

impl VerifiedArtifact {
    pub fn digest(&self) -> &ArtifactDigest {
        &self.digest
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceSource {
    Case(CaseId),
    Attempt(AttemptId),
    Commissioning(InstrumentId),
}

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
    root_directory: Arc<File>,
}

impl ArtifactStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, EvidenceError> {
        let root = normalize_root(root.into())?;
        let root_directory = open_store_root(&root)?;
        Ok(Self {
            root,
            root_directory: Arc::new(root_directory),
        })
    }

    pub fn publish(
        &self,
        bytes: &[u8],
        source: EvidenceSource,
    ) -> Result<ArtifactDigest, EvidenceError> {
        let digest = ArtifactDigest::sha256(bytes);
        let (directory, name, path) = self.artifact_location(&digest, true)?;
        if read_artifact_if_present(&directory, &name, &path, &digest, true)?.is_some() {
            self.record_source(&digest, &source)?;
            return Ok(digest);
        }

        let (mut temporary_file, temporary) = create_temporary(&directory, &digest)?;
        temporary_file
            .write_all(bytes)
            .map_err(|source| EvidenceError::Io { source })?;
        rustix::fs::fchmod(&temporary_file, FILE_MODE).map_err(io_error)?;
        temporary_file
            .sync_all()
            .map_err(|source| EvidenceError::Io { source })?;
        match rustix::fs::linkat(
            &directory,
            temporary.name(),
            &directory,
            name.as_os_str(),
            AtFlags::empty(),
        ) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(source) => return Err(io_error(source)),
        }
        drop(temporary_file);

        read_artifact_if_present(&directory, &name, &path, &digest, true)?.ok_or_else(|| {
            EvidenceError::Io {
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "published artifact disappeared before verification",
                ),
            }
        })?;
        temporary.remove()?;
        self.record_source(&digest, &source)?;
        Ok(digest)
    }

    pub fn read(&self, digest: &ArtifactDigest) -> Result<VerifiedArtifact, EvidenceError> {
        let (directory, name, path) = self.artifact_location(digest, false)?;
        read_artifact_if_present(&directory, &name, &path, digest, false)?.ok_or_else(|| {
            EvidenceError::Io {
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "evidence artifact does not exist",
                ),
            }
        })
    }

    pub fn verify_source(
        &self,
        digest: &ArtifactDigest,
        source: &EvidenceSource,
    ) -> Result<VerifiedArtifact, EvidenceError> {
        let artifact = self.read(digest)?;
        let (directory, name, path) = self.source_location(digest, source, false)?;
        let marker = open_regular_file(&directory, &name, &path, false)?;
        if marker
            .metadata()
            .map_err(|source| EvidenceError::Io { source })?
            .len()
            != 0
        {
            return Err(EvidenceError::InvalidEntry { path });
        }
        Ok(artifact)
    }

    pub fn path_for(&self, digest: &ArtifactDigest) -> PathBuf {
        let (prefix, suffix) = digest_components(digest);
        self.root.join("sha256").join(prefix).join(suffix)
    }

    fn artifact_location(
        &self,
        digest: &ArtifactDigest,
        create: bool,
    ) -> Result<(File, OsString, PathBuf), EvidenceError> {
        let (prefix, suffix) = digest_components(digest);
        let directory = self.descend(&["sha256", &prefix], create)?;
        let name = OsString::from(suffix);
        let path = self.path_for(digest);
        Ok((directory, name, path))
    }

    fn source_location(
        &self,
        digest: &ArtifactDigest,
        source: &EvidenceSource,
        create: bool,
    ) -> Result<(File, OsString, PathBuf), EvidenceError> {
        let (kind, id) = source_parts(source);
        let (prefix, suffix) = digest_components(digest);
        let components = ["references", "sha256", &prefix, &suffix, kind];
        let directory = self.descend(&components, create)?;
        let name = OsString::from(id);
        let path = components
            .into_iter()
            .fold(self.root.clone(), |path, component| path.join(component))
            .join(&name);
        Ok((directory, name, path))
    }

    fn descend(&self, components: &[&str], create: bool) -> Result<File, EvidenceError> {
        let mut directory = self
            .root_directory
            .try_clone()
            .map_err(|source| EvidenceError::Io { source })?;
        let mut path = self.root.clone();
        for component in components {
            path.push(component);
            directory = if create {
                ensure_store_directory(&directory, OsStr::new(component), &path)?
            } else {
                open_directory(&directory, OsStr::new(component), &path)?
            };
        }
        Ok(directory)
    }

    fn record_source(
        &self,
        digest: &ArtifactDigest,
        source: &EvidenceSource,
    ) -> Result<(), EvidenceError> {
        let (directory, name, path) = self.source_location(digest, source, true)?;
        match rustix::fs::openat(
            &directory,
            name.as_os_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            FILE_MODE,
        ) {
            Ok(file) => {
                let file = File::from(file);
                secure_regular_file(&file, &path)?;
                file.sync_all()
                    .map_err(|source| EvidenceError::Io { source })?;
                sync_directory(&directory)
            }
            Err(Errno::EXIST) => {
                let marker = open_regular_file(&directory, &name, &path, true)?;
                if marker
                    .metadata()
                    .map_err(|source| EvidenceError::Io { source })?
                    .len()
                    != 0
                {
                    return Err(EvidenceError::InvalidEntry { path });
                }
                marker
                    .sync_all()
                    .map_err(|source| EvidenceError::Io { source })?;
                sync_directory(&directory)
            }
            Err(source) => Err(open_error(source, path)),
        }
    }
}

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TemporaryEntry<'a> {
    directory: &'a File,
    name: OsString,
    is_present: bool,
}

impl TemporaryEntry<'_> {
    fn name(&self) -> &OsStr {
        &self.name
    }

    fn remove(mut self) -> Result<(), EvidenceError> {
        match rustix::fs::unlinkat(self.directory, self.name.as_os_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(source) => return Err(io_error(source)),
        }
        sync_directory(self.directory)?;
        self.is_present = false;
        Ok(())
    }
}

impl Drop for TemporaryEntry<'_> {
    fn drop(&mut self) {
        if !self.is_present {
            return;
        }
        match rustix::fs::unlinkat(self.directory, self.name.as_os_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {
                if let Err(source) = rustix::fs::fsync(self.directory) {
                    tracing::warn!(
                        error = %source,
                        temporary = %self.name.to_string_lossy(),
                        "failed to sync evidence temporary cleanup"
                    );
                }
            }
            Err(source) => {
                tracing::warn!(
                    error = %source,
                    temporary = %self.name.to_string_lossy(),
                    "failed to remove evidence temporary"
                );
            }
        }
    }
}

fn digest_components(digest: &ArtifactDigest) -> (String, String) {
    let mut characters = digest.as_str().chars();
    let prefix = characters.by_ref().take(2).collect();
    (prefix, characters.collect())
}

fn source_parts(source: &EvidenceSource) -> (&'static str, &str) {
    match source {
        EvidenceSource::Case(id) => ("case", id.as_str()),
        EvidenceSource::Attempt(id) => ("attempt", id.as_str()),
        EvidenceSource::Commissioning(id) => ("commissioning", id.as_str()),
    }
}

fn normalize_root(root: PathBuf) -> Result<PathBuf, EvidenceError> {
    if root.as_os_str().is_empty() {
        return Err(EvidenceError::InvalidRoot { path: root });
    }
    let original = root.clone();
    let absolute = if root.is_absolute() {
        root
    } else {
        std::env::current_dir()
            .map_err(|source| EvidenceError::Io { source })?
            .join(root)
    };
    let mut normalized = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(EvidenceError::InvalidRoot { path: original });
                }
            }
            Component::Normal(component) => normalized.push(component),
            Component::Prefix(_) => {
                return Err(EvidenceError::InvalidRoot { path: original });
            }
        }
    }
    if normalized == Path::new("/") {
        return Err(EvidenceError::InvalidRoot { path: original });
    }
    Ok(normalized)
}

fn open_store_root(root: &Path) -> Result<File, EvidenceError> {
    let mut directory = File::from(
        rustix::fs::openat(
            rustix::fs::CWD,
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io_error)?,
    );
    let components: Vec<_> = root
        .components()
        .filter_map(|component| match component {
            Component::Normal(component) => Some(component.to_owned()),
            _ => None,
        })
        .collect();
    let mut path = PathBuf::from("/");
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        directory =
            open_or_create_directory(&directory, component, &path, index + 1 == components.len())?;
    }
    Ok(directory)
}

fn open_or_create_directory(
    parent: &File,
    name: &OsStr,
    path: &Path,
    secure_existing: bool,
) -> Result<File, EvidenceError> {
    let (directory, created) = match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(directory) => (File::from(directory), false),
        Err(Errno::NOENT) => {
            let created = match rustix::fs::mkdirat(parent, name, DIRECTORY_MODE) {
                Ok(()) => true,
                Err(Errno::EXIST) => false,
                Err(source) => return Err(io_error(source)),
            };
            let directory = File::from(
                rustix::fs::openat(
                    parent,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|source| open_error(source, path.to_owned()))?,
            );
            (directory, created)
        }
        Err(source) => return Err(open_error(source, path.to_owned())),
    };
    if created || secure_existing {
        rustix::fs::fchmod(&directory, DIRECTORY_MODE).map_err(io_error)?;
        sync_directory(&directory)?;
        sync_directory(parent)?;
    }
    Ok(directory)
}

fn ensure_store_directory(parent: &File, name: &OsStr, path: &Path) -> Result<File, EvidenceError> {
    open_or_create_directory(parent, name, path, true)
}

fn open_directory(parent: &File, name: &OsStr, path: &Path) -> Result<File, EvidenceError> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|source| open_error(source, path.to_owned()))
}

fn open_regular_file(
    parent: &File,
    name: &OsStr,
    path: &Path,
    writable: bool,
) -> Result<File, EvidenceError> {
    let access = if writable {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    };
    let file = rustix::fs::openat(
        parent,
        name,
        access | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|source| open_error(source, path.to_owned()))?;
    validate_regular_file(&file, path)?;
    if writable {
        rustix::fs::fchmod(&file, FILE_MODE).map_err(io_error)?;
    }
    Ok(file)
}

fn secure_regular_file(file: &File, path: &Path) -> Result<(), EvidenceError> {
    validate_regular_file(file, path)?;
    rustix::fs::fchmod(file, FILE_MODE).map_err(io_error)
}

fn validate_regular_file(file: &File, path: &Path) -> Result<(), EvidenceError> {
    if !file
        .metadata()
        .map_err(|source| EvidenceError::Io { source })?
        .file_type()
        .is_file()
    {
        return Err(EvidenceError::InvalidEntry {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn read_artifact_if_present(
    directory: &File,
    name: &OsStr,
    path: &Path,
    digest: &ArtifactDigest,
    durable: bool,
) -> Result<Option<VerifiedArtifact>, EvidenceError> {
    let mut file = match open_regular_file(directory, name, path, durable) {
        Ok(file) => file,
        Err(EvidenceError::Io { source }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| EvidenceError::Io { source })?;
    if ArtifactDigest::sha256(&bytes) != *digest {
        return Err(EvidenceError::DigestMismatch {
            digest: digest.clone(),
        });
    }
    if durable {
        file.sync_all()
            .map_err(|source| EvidenceError::Io { source })?;
        sync_directory(directory)?;
    }
    Ok(Some(VerifiedArtifact {
        digest: digest.clone(),
        bytes,
    }))
}

fn create_temporary<'a>(
    directory: &'a File,
    digest: &ArtifactDigest,
) -> Result<(File, TemporaryEntry<'a>), EvidenceError> {
    loop {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = OsString::from(format!(
            ".{}.{}.{}.partial",
            digest.as_str(),
            std::process::id(),
            sequence
        ));
        match rustix::fs::openat(
            directory,
            name.as_os_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            FILE_MODE,
        ) {
            Ok(file) => {
                return Ok((
                    File::from(file),
                    TemporaryEntry {
                        directory,
                        name,
                        is_present: true,
                    },
                ));
            }
            Err(Errno::EXIST) => {}
            Err(source) => return Err(io_error(source)),
        }
    }
}

fn sync_directory(directory: &File) -> Result<(), EvidenceError> {
    rustix::fs::fsync(directory).map_err(io_error)
}

fn io_error(source: Errno) -> EvidenceError {
    EvidenceError::Io {
        source: source.into(),
    }
}

fn open_error(source: Errno, path: PathBuf) -> EvidenceError {
    if matches!(source, Errno::ISDIR | Errno::LOOP | Errno::NOTDIR) {
        EvidenceError::InvalidEntry { path }
    } else {
        io_error(source)
    }
}
