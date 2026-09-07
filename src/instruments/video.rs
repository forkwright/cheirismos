//! Bounded, identity-checked UVC frame capture through a configured executable.
//!
//! The adapter deliberately returns only raw PNG bytes and the observed USB
//! identity. Frame interpretation is a separate, explicitly governed operation.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use epitelesis::{CapturePolicy, Command};
use sha2::{Digest, Sha256};

use super::{InstrumentError, VideoConfig};

const SYSFS_VIDEO_ROOT: &str = "/sys/class/video4linux";
const STDERR_LIMIT: usize = 64 * 1024;
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// USB identity observed from the configured V4L2 device's sysfs ancestry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoIdentity {
    pub usb_identity: String,
}

/// One raw frame. `png` has only container-level signature validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    pub png: Vec<u8>,
    pub identity: VideoIdentity,
}

/// Fixed-purpose adapter for a supervisor-owned UVC device binding.
pub struct VideoAdapter {
    config: VideoConfig,
    sysfs_video_root: PathBuf,
}

impl VideoAdapter {
    /// Validates the server-owned configuration. Device presence is checked for
    /// every inspection and capture, immediately before its use.
    pub fn new(config: &VideoConfig) -> Result<Self, InstrumentError> {
        Self::with_sysfs_root(config, PathBuf::from(SYSFS_VIDEO_ROOT))
    }

    /// Observe the connected USB identity without starting a capture process.
    pub fn inspect(&self) -> Result<VideoIdentity, InstrumentError> {
        inspect_identity(&self.config, &self.sysfs_video_root)
    }

    /// Verify executable bytes and current USB identity, then capture exactly one PNG frame.
    pub fn capture(&self) -> Result<VideoFrame, InstrumentError> {
        verify_executable_digest(&self.config)?;
        let identity = self.inspect()?;
        let command = Command::new(&self.config.executable)
            .args(["-hide_banner", "-loglevel", "error", "-f", "v4l2", "-i"])
            .arg(&self.config.device_path)
            .args(["-frames:v", "1", "-f", "image2pipe", "-vcodec", "png", "-"])
            .clean_environment()
            .capture_stdout(CapturePolicy::bounded(self.config.max_frame_bytes))
            .capture_stderr(CapturePolicy::bounded(STDERR_LIMIT))
            .deadline(Duration::from_millis(
                self.config.frame_timeout_milliseconds,
            ))
            .map_err(|error| InstrumentError::VideoCaptureFailed {
                detail: error.to_string(),
            })?;
        let output = epitelesis::run(command)
            .map_err(|error| map_capture_error(error, self.config.max_frame_bytes))?;
        let png = output.evidence.stdout.captured.bytes;
        if !png.starts_with(PNG_SIGNATURE) {
            return Err(InstrumentError::InvalidVideoFrame);
        }
        Ok(VideoFrame { png, identity })
    }

    fn with_sysfs_root(
        config: &VideoConfig,
        sysfs_video_root: PathBuf,
    ) -> Result<Self, InstrumentError> {
        validate_config(config)?;
        Ok(Self {
            config: config.clone(),
            sysfs_video_root,
        })
    }
}

/// Inspect one configured device without starting a subprocess.
pub fn inspect_video(config: &VideoConfig) -> Result<VideoIdentity, InstrumentError> {
    VideoAdapter::new(config)?.inspect()
}

/// Capture one configured frame synchronously for the supervisor backend.
pub fn capture_video(config: &VideoConfig) -> Result<VideoFrame, InstrumentError> {
    VideoAdapter::new(config)?.capture()
}

fn validate_config(config: &VideoConfig) -> Result<(), InstrumentError> {
    config.validate()?;
    if !config.device_path.is_absolute() {
        return Err(InstrumentError::InvalidVideoConfiguration {
            detail: "device_path must be absolute".to_owned(),
        });
    }
    if !config.executable.is_absolute() {
        return Err(InstrumentError::InvalidVideoConfiguration {
            detail: "executable must be absolute".to_owned(),
        });
    }
    let identity = parse_identity(&config.expected_usb_identity)?;
    if identity.serial.is_empty() {
        return Err(InstrumentError::InvalidVideoConfiguration {
            detail: "expected_usb_identity serial must not be empty".to_owned(),
        });
    }
    Ok(())
}

fn verify_executable_digest(config: &VideoConfig) -> Result<(), InstrumentError> {
    let mut executable =
        fs::File::open(&config.executable).map_err(|source| InstrumentError::Io {
            action: "opening configured video executable",
            source,
        })?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = executable
            .read(&mut buffer)
            .map_err(|source| InstrumentError::Io {
                action: "hashing configured video executable",
                source,
            })?;
        if count == 0 {
            break;
        }
        let chunk = buffer.get(..count).ok_or(InstrumentError::ProtocolLimit {
            requested: count,
            limit: buffer.len(),
        })?;
        digest.update(chunk);
    }
    let actual = hex::encode(digest.finalize());
    if actual != config.executable_sha256 {
        return Err(InstrumentError::VideoExecutableDigestMismatch {
            expected: config.executable_sha256.clone(),
            actual,
        });
    }
    Ok(())
}

fn inspect_identity(
    config: &VideoConfig,
    sysfs_video_root: &Path,
) -> Result<VideoIdentity, InstrumentError> {
    let expected = parse_identity(&config.expected_usb_identity)?;
    let device_name = config.device_path.file_name().ok_or_else(|| {
        InstrumentError::InvalidVideoConfiguration {
            detail: "device_path must name a V4L2 device".to_owned(),
        }
    })?;
    let start =
        fs::canonicalize(sysfs_video_root.join(device_name).join("device")).map_err(|source| {
            InstrumentError::Io {
                action: "resolving configured video sysfs device",
                source,
            }
        })?;
    let candidates = usb_identities_in_ancestry(&start)?;
    let observed = match candidates.as_slice() {
        [identity] => identity.clone(),
        [] => {
            return Err(InstrumentError::VideoIdentityMismatch {
                expected: config.expected_usb_identity.clone(),
                actual: "absent from video device sysfs ancestry".to_owned(),
            });
        }
        _ => {
            return Err(InstrumentError::VideoIdentityMismatch {
                expected: config.expected_usb_identity.clone(),
                actual: format!("ambiguous USB ancestry: {} identities", candidates.len()),
            });
        }
    };
    if observed != expected.render() {
        return Err(InstrumentError::VideoIdentityMismatch {
            expected: config.expected_usb_identity.clone(),
            actual: observed,
        });
    }
    Ok(VideoIdentity {
        usb_identity: expected.render(),
    })
}

fn usb_identities_in_ancestry(start: &Path) -> Result<Vec<String>, InstrumentError> {
    let mut identities = Vec::new();
    let mut current = Some(start);
    while let Some(path) = current {
        let vendor = read_sysfs_value(path, "idVendor")?;
        let product = read_sysfs_value(path, "idProduct")?;
        let serial = read_sysfs_value(path, "serial")?;
        if let (Some(vendor), Some(product), Some(serial)) = (vendor, product, serial) {
            identities.push(format!("{vendor}:{product}:{serial}"));
        }
        current = path.parent();
    }
    Ok(identities)
}

fn read_sysfs_value(path: &Path, name: &str) -> Result<Option<String>, InstrumentError> {
    let candidate = path.join(name);
    match fs::read_to_string(candidate) {
        Ok(value) => Ok(Some(value.trim().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(InstrumentError::Io {
            action: "reading video USB sysfs identity",
            source,
        }),
    }
}

struct ParsedIdentity {
    vendor: String,
    product: String,
    serial: String,
}

impl ParsedIdentity {
    fn render(&self) -> String {
        format!("{}:{}:{}", self.vendor, self.product, self.serial)
    }
}

fn parse_identity(value: &str) -> Result<ParsedIdentity, InstrumentError> {
    let mut parts = value.split(':');
    let vendor = parts.next().unwrap_or_default();
    let product = parts.next().unwrap_or_default();
    let serial = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || !is_hex_word(vendor)
        || !is_hex_word(product)
        || serial.trim().is_empty()
    {
        return Err(InstrumentError::InvalidVideoConfiguration {
            detail: "expected_usb_identity must be lowercase vid:pid:serial".to_owned(),
        });
    }
    Ok(ParsedIdentity {
        vendor: vendor.to_owned(),
        product: product.to_owned(),
        serial: serial.to_owned(),
    })
}

fn is_hex_word(value: &str) -> bool {
    value.len() == 4
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

fn map_capture_error(error: epitelesis::Error, max_frame_bytes: usize) -> InstrumentError {
    match error {
        epitelesis::Error::Timeout { .. } => InstrumentError::Timeout {
            operation: "capturing video frame",
        },
        epitelesis::Error::CaptureLimitExceeded { .. } => InstrumentError::FrameTooLarge {
            limit: max_frame_bytes,
        },
        other => InstrumentError::VideoCaptureFailed {
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };

    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{InstrumentError, VideoAdapter, VideoConfig};

    #[test]
    fn captures_one_raw_png_from_a_hashed_executable() {
        let fixture = fixture("printf '\\211PNG\\r\\n\\032\\nframe'");
        let adapter = VideoAdapter::with_sysfs_root(&fixture.config, fixture.sysfs_root)
            .unwrap_or_else(|error| panic!("adapter: {error}"));
        let frame = adapter
            .capture()
            .unwrap_or_else(|error| panic!("capture: {error}"));
        assert_eq!(frame.identity.usb_identity, "1a2b:3c4d:camera-7");
        assert_eq!(&frame.png[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn rejects_wrong_executable_hash_before_launch() {
        let mut fixture = fixture("printf '\\211PNG\\r\\n\\032\\nframe'");
        fixture.config.executable_sha256 = "0".repeat(64);
        let adapter = VideoAdapter::with_sysfs_root(&fixture.config, fixture.sysfs_root)
            .unwrap_or_else(|error| panic!("adapter: {error}"));
        assert!(matches!(
            adapter.capture(),
            Err(InstrumentError::VideoExecutableDigestMismatch { .. })
        ));
    }

    #[test]
    fn rejects_capture_output_over_the_configured_limit() {
        let mut fixture =
            fixture("printf '\\211PNG\\r\\n\\032\\n0123456789012345678901234567890123456789'");
        fixture.config.max_frame_bytes = 16;
        fixture.config.executable_sha256 = digest(&fixture.config.executable);
        let adapter = VideoAdapter::with_sysfs_root(&fixture.config, fixture.sysfs_root)
            .unwrap_or_else(|error| panic!("adapter: {error}"));
        assert!(matches!(
            adapter.capture(),
            Err(InstrumentError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn terminates_a_timed_out_capture() {
        let fixture = fixture("sleep 1; printf '\\211PNG\\r\\n\\032\\nlate'");
        let mut config = fixture.config;
        config.frame_timeout_milliseconds = 20;
        let adapter = VideoAdapter::with_sysfs_root(&config, fixture.sysfs_root)
            .unwrap_or_else(|error| panic!("adapter: {error}"));
        assert!(matches!(
            adapter.capture(),
            Err(InstrumentError::Timeout { .. })
        ));
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        config: VideoConfig,
        sysfs_root: PathBuf,
    }

    fn fixture(body: &str) -> Fixture {
        let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
        let executable = directory.path().join("fake-ffmpeg");
        fs::write(&executable, format!("#!/bin/sh\n{body}\n"))
            .unwrap_or_else(|error| panic!("write fake executable: {error}"));
        let mut permissions = fs::metadata(&executable)
            .unwrap_or_else(|error| panic!("executable metadata: {error}"))
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions)
            .unwrap_or_else(|error| panic!("make fake executable: {error}"));

        let sysfs_root = directory.path().join("sysfs");
        let device = sysfs_root.join("video-test").join("device");
        fs::create_dir_all(&device).unwrap_or_else(|error| panic!("create fake sysfs: {error}"));
        fs::write(device.join("idVendor"), "1a2b\n")
            .unwrap_or_else(|error| panic!("write vendor: {error}"));
        fs::write(device.join("idProduct"), "3c4d\n")
            .unwrap_or_else(|error| panic!("write product: {error}"));
        fs::write(device.join("serial"), "camera-7\n")
            .unwrap_or_else(|error| panic!("write serial: {error}"));
        Fixture {
            config: VideoConfig {
                device_path: Path::new("/dev/video-test").to_path_buf(),
                expected_usb_identity: "1a2b:3c4d:camera-7".to_owned(),
                executable: executable.clone(),
                executable_sha256: digest(&executable),
                frame_timeout_milliseconds: 200,
                max_frame_bytes: 1024,
            },
            _directory: directory,
            sysfs_root,
        }
    }

    fn digest(path: &Path) -> String {
        let bytes = fs::read(path).unwrap_or_else(|error| panic!("read executable: {error}"));
        hex::encode(Sha256::digest(bytes))
    }
}
