//! Pure, offline firmware-byte inspection and candidate composition.
//!
//! The evidence in this module describes supplied bytes. It does not establish
//! firmware provenance, compatibility, signature validity, chip count, or any
//! authority to operate hardware.

use std::collections::HashSet;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::{Location, Snafu, ensure};

/// The largest number of changed ranges retained in a diff report.
pub const MAX_REPORTED_DIFF_RANGES: usize = 4_096;

const IDENTIFICATION_STRING_LIMIT: usize = 256;
const MINIMUM_IDENTIFICATION_STRING_BYTES: usize = 4;
const REPEATED_CHUNK_BYTES: usize = 4_096;

/// Explains the narrow scope of every firmware-byte report in this module.
pub const FIRMWARE_EVIDENCE_INTERPRETATION: &str = "Offline byte evidence only. It does not prove firmware provenance, compatibility, signature validity, physical chip count, electrical safety, or bootability. It grants no hardware authority.";

/// A validated lowercase hexadecimal SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest(String);

/// A half-open byte range with a nonzero length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "RawByteRange", into = "RawByteRange")]
pub struct ByteRange {
    start_byte: u64,
    end_byte_exclusive: u64,
}

/// A bounded replacement of one byte range in an original image.
///
/// `build_candidate` verifies that the replacement length exactly matches the
/// range before it copies any bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImagePatch {
    /// The original-image bytes replaced by `replacement`.
    pub range: ByteRange,
    /// The bytes to place in `range` after validation.
    pub replacement: Vec<u8>,
}

/// Direct facts observed while inspecting one supplied image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageInspection {
    /// The number of supplied bytes.
    pub size_bytes: u64,
    /// The SHA-256 digest of exactly the supplied bytes.
    pub sha256: Sha256Digest,
    /// The byte value when every supplied byte is identical.
    pub uniform_byte: Option<u8>,
    /// Repetition facts for complete fixed-size chunks, when repetition exists.
    pub repeated_chunk_evidence: Option<RepeatedChunkEvidence>,
    /// Printable ASCII runs that may aid later human identification.
    pub identification_strings: Vec<IdentificationStringEvidence>,
    /// Whether `identification_strings` reached its reporting bound.
    pub identification_strings_truncated: bool,
    /// The interpretation boundary for this observation.
    pub interpretation: String,
}

/// A count-based observation that complete byte chunks repeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepeatedChunkEvidence {
    /// The fixed chunk size used for this observation.
    pub chunk_size_bytes: u64,
    /// The number of complete chunks inspected.
    pub complete_chunk_count: u64,
    /// The number of complete chunks beyond the first occurrence of their bytes.
    pub repeated_chunk_count: u64,
}

/// A printable ASCII run observed in supplied bytes without semantic inference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentificationStringEvidence {
    /// The zero-based byte offset of the printable ASCII run.
    pub start_byte: u64,
    /// The observed printable ASCII text.
    pub text: String,
}

/// A byte-level comparison of two equal-sized supplied images.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageComparison {
    /// Facts observed in the left image.
    pub left: ImageInspection,
    /// Facts observed in the right image.
    pub right: ImageInspection,
    /// Number of differing byte positions.
    pub changed_bytes: u64,
    /// Total number of changed runs, including runs omitted from `changed_ranges`.
    pub changed_range_count: u64,
    /// Whether every changed run appears in `changed_ranges`.
    pub ranges_complete: bool,
    /// The first changed runs, represented as half-open byte ranges.
    pub changed_ranges: Vec<ByteRange>,
    /// The interpretation boundary for this comparison.
    pub interpretation: String,
}

/// Bytes and evidence produced by a validated candidate composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateImage {
    bytes: Vec<u8>,
    evidence: CandidateEvidence,
}

/// Facts needed to bind a candidate image to its verified source and patches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidence {
    /// Digest that the supplied original matched before composition.
    pub original_sha256: Sha256Digest,
    /// Digest of the composed candidate bytes.
    pub candidate_sha256: Sha256Digest,
    /// Original-image ranges modified by the accepted patches.
    pub modified_ranges: Vec<ByteRange>,
    /// The interpretation boundary for this candidate.
    pub interpretation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawByteRange {
    start_byte: u64,
    end_byte_exclusive: u64,
}

/// Errors returned when supplied byte evidence cannot meet this module's contract.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum FirmwareError {
    /// A range is empty or has reversed bounds.
    #[snafu(display(
        "byte range [{start_byte}, {end_byte_exclusive}) must have a positive length"
    ))]
    InvalidRange {
        /// Requested start offset.
        start_byte: u64,
        /// Requested exclusive end offset.
        end_byte_exclusive: u64,
        #[snafu(implicit)]
        location: Location,
    },
    /// A digest is not exactly 64 lowercase hexadecimal characters.
    #[snafu(display("SHA-256 digest must be 64 lowercase hexadecimal characters"))]
    InvalidSha256Digest {
        #[snafu(implicit)]
        location: Location,
    },
    /// An image length cannot be represented in the portable evidence format.
    #[snafu(display("image length cannot be represented as a 64-bit byte count"))]
    ImageLengthTooLarge {
        #[snafu(implicit)]
        location: Location,
    },
    /// A requested diff limit is outside the bounded report contract.
    #[snafu(display("max_ranges must be in [1, {MAX_REPORTED_DIFF_RANGES}]"))]
    InvalidDiffRangeLimit {
        #[snafu(implicit)]
        location: Location,
    },
    /// Images have different byte lengths and cannot be compared without padding.
    #[snafu(display(
        "image comparison requires equal lengths, got {left_bytes} and {right_bytes}"
    ))]
    ImageLengthMismatch {
        /// Left image size.
        left_bytes: u64,
        /// Right image size.
        right_bytes: u64,
        #[snafu(implicit)]
        location: Location,
    },
    /// The supplied original does not match the requested base digest.
    #[snafu(display("candidate base digest mismatch: expected {expected}, got {actual}"))]
    CandidateBaseDigestMismatch {
        /// Digest the caller required for the original.
        expected: Sha256Digest,
        /// Digest calculated from the supplied original.
        actual: Sha256Digest,
        #[snafu(implicit)]
        location: Location,
    },
    /// A patch or protected range extends beyond the supplied original.
    #[snafu(display("{kind} range {range} exceeds original image size {image_size_bytes}"))]
    RangeOutOfBounds {
        /// The role of the invalid range.
        kind: &'static str,
        /// The range that exceeds the original.
        range: ByteRange,
        /// The original image length.
        image_size_bytes: u64,
        #[snafu(implicit)]
        location: Location,
    },
    /// A replacement does not exactly preserve the original image length.
    #[snafu(display(
        "patch {patch_index} replacement length {replacement_bytes} does not match range length {range_bytes}"
    ))]
    PatchLengthMismatch {
        /// Position of the patch in the supplied patch list.
        patch_index: usize,
        /// Length of the replacement bytes.
        replacement_bytes: usize,
        /// Length of the target range.
        range_bytes: u64,
        #[snafu(implicit)]
        location: Location,
    },
    /// Two supplied patches would write at least one common original byte.
    #[snafu(display("patches {first_patch_index} and {second_patch_index} overlap"))]
    OverlappingPatches {
        /// Position of the first conflicting patch in the supplied patch list.
        first_patch_index: usize,
        /// Position of the second conflicting patch in the supplied patch list.
        second_patch_index: usize,
        #[snafu(implicit)]
        location: Location,
    },
    /// A supplied patch would alter a caller-protected original range.
    #[snafu(display("patch {patch_index} overlaps protected range {protected_range}"))]
    PatchTouchesProtectedRange {
        /// Position of the conflicting patch in the supplied patch list.
        patch_index: usize,
        /// The protected range that blocks that patch.
        protected_range: ByteRange,
        #[snafu(implicit)]
        location: Location,
    },
}

impl Sha256Digest {
    /// Returns this validated digest as lowercase hexadecimal text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = FirmwareError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ensure!(
            value.len() == Sha256::output_size() * 2
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            InvalidSha256DigestSnafu
        );
        Ok(Self(value))
    }
}

impl TryFrom<&str> for Sha256Digest {
    type Error = FirmwareError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.0
    }
}

impl AsRef<str> for Sha256Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl ByteRange {
    /// Constructs a nonempty half-open byte range.
    ///
    /// # Errors
    ///
    /// Returns `FirmwareError::InvalidRange` when `end_byte_exclusive` is not
    /// greater than `start_byte`.
    pub fn new(start_byte: u64, end_byte_exclusive: u64) -> Result<Self, FirmwareError> {
        ensure!(
            start_byte < end_byte_exclusive,
            InvalidRangeSnafu {
                start_byte,
                end_byte_exclusive,
            }
        );
        Ok(Self {
            start_byte,
            end_byte_exclusive,
        })
    }

    /// Returns the zero-based start offset.
    #[must_use]
    pub const fn start_byte(self) -> u64 {
        self.start_byte
    }

    /// Returns the exclusive end offset.
    #[must_use]
    pub const fn end_byte_exclusive(self) -> u64 {
        self.end_byte_exclusive
    }

    /// Returns the number of bytes in this range.
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.end_byte_exclusive - self.start_byte
    }

    fn overlaps(self, other: Self) -> bool {
        self.start_byte < other.end_byte_exclusive && other.start_byte < self.end_byte_exclusive
    }
}

impl TryFrom<RawByteRange> for ByteRange {
    type Error = FirmwareError;

    fn try_from(value: RawByteRange) -> Result<Self, Self::Error> {
        Self::new(value.start_byte, value.end_byte_exclusive)
    }
}

impl From<ByteRange> for RawByteRange {
    fn from(value: ByteRange) -> Self {
        Self {
            start_byte: value.start_byte,
            end_byte_exclusive: value.end_byte_exclusive,
        }
    }
}

impl fmt::Display for ByteRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}, {})",
            self.start_byte, self.end_byte_exclusive
        )
    }
}

impl CandidateImage {
    /// Borrows the fully composed bytes for explicit storage by the caller.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the evidence that binds this candidate to its base and patches.
    #[must_use]
    pub fn evidence(&self) -> &CandidateEvidence {
        &self.evidence
    }

    /// Returns the fully composed bytes for caller-controlled storage.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Calculates the SHA-256 digest of exactly the supplied bytes.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    Sha256Digest(hex::encode(digest))
}

/// Inspects supplied bytes without parsing a platform-specific firmware format.
///
/// Printable strings and repeated chunks are observations only. The function
/// does not classify firmware, validate signatures, or infer physical media.
///
/// # Errors
///
/// Returns `FirmwareError::ImageLengthTooLarge` if the input length cannot be
/// represented by the portable report format.
pub fn inspect_image(bytes: &[u8]) -> Result<ImageInspection, FirmwareError> {
    let size_bytes = image_size(bytes)?;
    let uniform_byte = bytes.first().copied().filter(|first_byte| {
        bytes
            .iter()
            .all(|candidate_byte| candidate_byte == first_byte)
    });
    let repeated_chunk_evidence = repeated_chunk_evidence(bytes)?;
    let (identification_strings, identification_strings_truncated) = identification_strings(bytes)?;

    Ok(ImageInspection {
        size_bytes,
        sha256: sha256_digest(bytes),
        uniform_byte,
        repeated_chunk_evidence,
        identification_strings,
        identification_strings_truncated,
        interpretation: FIRMWARE_EVIDENCE_INTERPRETATION.to_owned(),
    })
}

/// Compares equal-sized supplied images and reports half-open changed ranges.
///
/// The comparison never pads, truncates, composes, or approves either image.
///
/// # Errors
///
/// Returns `FirmwareError::ImageLengthMismatch` for unequal images and
/// `FirmwareError::InvalidDiffRangeLimit` for an unbounded report request.
pub fn compare_images(
    left: &[u8],
    right: &[u8],
    max_ranges: usize,
) -> Result<ImageComparison, FirmwareError> {
    ensure!(
        (1..=MAX_REPORTED_DIFF_RANGES).contains(&max_ranges),
        InvalidDiffRangeLimitSnafu
    );

    let left_size_bytes = image_size(left)?;
    let right_size_bytes = image_size(right)?;
    ensure!(
        left_size_bytes == right_size_bytes,
        ImageLengthMismatchSnafu {
            left_bytes: left_size_bytes,
            right_bytes: right_size_bytes,
        }
    );

    let mut changed_bytes = 0_u64;
    let mut changed_range_count = 0_u64;
    let mut changed_range_start = None;
    let mut changed_ranges = Vec::new();

    for (index, (&left_byte, &right_byte)) in left.iter().zip(right).enumerate() {
        if left_byte != right_byte {
            changed_bytes += 1;
            changed_range_start.get_or_insert(index);
        } else if let Some(start) = changed_range_start.take() {
            changed_range_count += 1;
            append_changed_range(&mut changed_ranges, max_ranges, start, index)?;
        }
    }
    if let Some(start) = changed_range_start {
        changed_range_count += 1;
        append_changed_range(&mut changed_ranges, max_ranges, start, left.len())?;
    }

    Ok(ImageComparison {
        left: inspect_image(left)?,
        right: inspect_image(right)?,
        changed_bytes,
        changed_range_count,
        ranges_complete: changed_range_count
            == u64::try_from(changed_ranges.len()).map_err(|_| ImageLengthTooLargeSnafu.build())?,
        changed_ranges,
        interpretation: FIRMWARE_EVIDENCE_INTERPRETATION.to_owned(),
    })
}

/// Builds an equal-sized candidate by applying disjoint, bounded patches.
///
/// The caller supplies the digest that the original must match and any ranges
/// that this operation must preserve. The result contains bytes only in memory;
/// storage, review, and hardware authority remain outside this module.
///
/// # Errors
///
/// Returns a typed error when the base digest differs, a range lies outside the
/// original, a replacement changes length, patches overlap, or a patch touches
/// a protected range.
pub fn build_candidate(
    original: &[u8],
    expected_original_sha256: &Sha256Digest,
    patches: &[ImagePatch],
    protected_ranges: &[ByteRange],
) -> Result<CandidateImage, FirmwareError> {
    let original_size_bytes = image_size(original)?;
    let actual_original_sha256 = sha256_digest(original);
    ensure!(
        actual_original_sha256 == *expected_original_sha256,
        CandidateBaseDigestMismatchSnafu {
            expected: expected_original_sha256.clone(),
            actual: actual_original_sha256,
        }
    );

    for protected_range in protected_ranges {
        validate_range_within_image(*protected_range, original_size_bytes, "protected")?;
    }

    let mut ordered_patches: Vec<(usize, &ImagePatch)> = patches.iter().enumerate().collect();
    ordered_patches.sort_by_key(|(_, patch)| patch.range.start_byte());

    for (position, (patch_index, patch)) in ordered_patches.iter().enumerate() {
        validate_range_within_image(patch.range, original_size_bytes, "patch")?;
        let replacement_bytes = patch.replacement.len();
        let range_bytes = patch.range.byte_len();
        ensure!(
            u64::try_from(replacement_bytes).map_err(|_| ImageLengthTooLargeSnafu.build())?
                == range_bytes,
            PatchLengthMismatchSnafu {
                patch_index: *patch_index,
                replacement_bytes,
                range_bytes,
            }
        );
        if let Some((previous_patch_index, previous_patch)) = position
            .checked_sub(1)
            .and_then(|previous| ordered_patches.get(previous))
            && previous_patch.range.overlaps(patch.range)
        {
            return OverlappingPatchesSnafu {
                first_patch_index: *previous_patch_index,
                second_patch_index: *patch_index,
            }
            .fail();
        }
        if let Some(protected_range) = protected_ranges
            .iter()
            .find(|protected_range| patch.range.overlaps(**protected_range))
        {
            return PatchTouchesProtectedRangeSnafu {
                patch_index: *patch_index,
                protected_range: *protected_range,
            }
            .fail();
        }
    }

    let mut candidate = original.to_vec();
    for (_, patch) in &ordered_patches {
        let start = usize::try_from(patch.range.start_byte())
            .map_err(|_| ImageLengthTooLargeSnafu.build())?;
        let end = usize::try_from(patch.range.end_byte_exclusive())
            .map_err(|_| ImageLengthTooLargeSnafu.build())?;
        candidate
            .get_mut(start..end)
            .ok_or_else(|| {
                RangeOutOfBoundsSnafu {
                    kind: "patch",
                    range: patch.range,
                    image_size_bytes: original_size_bytes,
                }
                .build()
            })?
            .copy_from_slice(&patch.replacement);
    }

    Ok(CandidateImage {
        evidence: CandidateEvidence {
            original_sha256: expected_original_sha256.clone(),
            candidate_sha256: sha256_digest(&candidate),
            modified_ranges: ordered_patches
                .iter()
                .map(|(_, patch)| patch.range)
                .collect(),
            interpretation: FIRMWARE_EVIDENCE_INTERPRETATION.to_owned(),
        },
        bytes: candidate,
    })
}

fn image_size(bytes: &[u8]) -> Result<u64, FirmwareError> {
    u64::try_from(bytes.len()).map_err(|_| ImageLengthTooLargeSnafu.build())
}

fn repeated_chunk_evidence(bytes: &[u8]) -> Result<Option<RepeatedChunkEvidence>, FirmwareError> {
    let complete_chunk_count = bytes.len() / REPEATED_CHUNK_BYTES;
    let mut unique_chunks = HashSet::with_capacity(complete_chunk_count);
    let mut repeated_chunk_count = 0_usize;
    for chunk in bytes.chunks_exact(REPEATED_CHUNK_BYTES) {
        if !unique_chunks.insert(chunk) {
            repeated_chunk_count += 1;
        }
    }
    if repeated_chunk_count == 0 {
        return Ok(None);
    }

    Ok(Some(RepeatedChunkEvidence {
        chunk_size_bytes: u64::try_from(REPEATED_CHUNK_BYTES)
            .map_err(|_| ImageLengthTooLargeSnafu.build())?,
        complete_chunk_count: u64::try_from(complete_chunk_count)
            .map_err(|_| ImageLengthTooLargeSnafu.build())?,
        repeated_chunk_count: u64::try_from(repeated_chunk_count)
            .map_err(|_| ImageLengthTooLargeSnafu.build())?,
    }))
}

fn identification_strings(
    bytes: &[u8],
) -> Result<(Vec<IdentificationStringEvidence>, bool), FirmwareError> {
    let mut evidence = Vec::new();
    let mut run_start = None;
    let mut truncated = false;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' {
            run_start.get_or_insert(index);
        } else if let Some(start) = run_start.take() {
            record_identification_string(&mut evidence, &mut truncated, bytes, start, index)?;
        }
    }
    if let Some(start) = run_start {
        record_identification_string(&mut evidence, &mut truncated, bytes, start, bytes.len())?;
    }

    Ok((evidence, truncated))
}

fn record_identification_string(
    evidence: &mut Vec<IdentificationStringEvidence>,
    truncated: &mut bool,
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<(), FirmwareError> {
    if end - start < MINIMUM_IDENTIFICATION_STRING_BYTES {
        return Ok(());
    }
    if evidence.len() == IDENTIFICATION_STRING_LIMIT {
        *truncated = true;
        return Ok(());
    }

    let text = bytes
        .iter()
        .skip(start)
        .take(end - start)
        .map(|byte| char::from(*byte))
        .collect();
    evidence.push(IdentificationStringEvidence {
        start_byte: u64::try_from(start).map_err(|_| ImageLengthTooLargeSnafu.build())?,
        text,
    });
    Ok(())
}

fn append_changed_range(
    changed_ranges: &mut Vec<ByteRange>,
    max_ranges: usize,
    start: usize,
    end: usize,
) -> Result<(), FirmwareError> {
    if changed_ranges.len() < max_ranges {
        changed_ranges.push(ByteRange::new(
            u64::try_from(start).map_err(|_| ImageLengthTooLargeSnafu.build())?,
            u64::try_from(end).map_err(|_| ImageLengthTooLargeSnafu.build())?,
        )?);
    }
    Ok(())
}

fn validate_range_within_image(
    range: ByteRange,
    image_size_bytes: u64,
    kind: &'static str,
) -> Result<(), FirmwareError> {
    ensure!(
        range.end_byte_exclusive() <= image_size_bytes,
        RangeOutOfBoundsSnafu {
            kind,
            range,
            image_size_bytes,
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ByteRange, FirmwareError, ImagePatch, MAX_REPORTED_DIFF_RANGES, Sha256Digest,
        build_candidate, compare_images, inspect_image, sha256_digest,
    };

    fn range(start_byte: u64, end_byte_exclusive: u64) -> ByteRange {
        ByteRange::new(start_byte, end_byte_exclusive).unwrap_or_else(|error| {
            panic!("test range must be valid: {error}");
        })
    }

    #[test]
    fn inspection_reports_digest_blank_bytes_repetition_and_ascii_evidence() {
        let mut image = vec![b'A'; 12_288];
        image[64..72].copy_from_slice(b"BOARD-ID");

        let inspection = inspect_image(&image).unwrap_or_else(|error| {
            panic!("inspection must succeed: {error}");
        });

        assert_eq!(
            inspection.size_bytes, 12_288,
            "inspection must retain length"
        );
        assert_eq!(
            inspection.sha256,
            sha256_digest(&image),
            "digest must bind bytes"
        );
        assert_eq!(inspection.uniform_byte, None, "mixed bytes are not blank");
        assert_eq!(
            inspection
                .repeated_chunk_evidence
                .as_ref()
                .map(|evidence| evidence.repeated_chunk_count),
            Some(1),
            "duplicate complete chunks must be reported"
        );
        assert!(
            inspection
                .identification_strings
                .iter()
                .any(|evidence| evidence.text.contains("BOARD-ID")),
            "printable byte runs must be retained as evidence"
        );
    }

    #[test]
    fn inspection_marks_uniform_zero_and_ff_images_without_interpreting_them() {
        for byte in [0, u8::MAX] {
            let inspection = inspect_image(&[byte; 32]).unwrap_or_else(|error| {
                panic!("inspection must succeed: {error}");
            });
            assert_eq!(
                inspection.uniform_byte,
                Some(byte),
                "uniform byte must be explicit"
            );
            assert!(
                inspection.interpretation.contains("does not prove"),
                "report must retain its interpretation boundary"
            );
        }
    }

    #[test]
    fn diff_reports_half_open_ranges_and_bounded_truncation() {
        let left = [0_u8; 10];
        let right = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0];

        let comparison = compare_images(&left, &right, 2).unwrap_or_else(|error| {
            panic!("comparison must succeed: {error}");
        });

        assert_eq!(comparison.changed_bytes, 5, "every differing byte counts");
        assert_eq!(comparison.changed_range_count, 5, "all changed runs count");
        assert_eq!(comparison.changed_ranges, vec![range(0, 1), range(2, 3)]);
        assert!(
            !comparison.ranges_complete,
            "bounded report must disclose truncation"
        );
    }

    #[test]
    fn diff_rejects_unequal_sizes_and_invalid_range_bounds() {
        let mismatch = compare_images(&[0], &[0, 1], 1).err();
        assert!(
            matches!(mismatch, Some(FirmwareError::ImageLengthMismatch { .. })),
            "comparison must not pad unequal images"
        );

        let invalid_limit = compare_images(&[0], &[0], MAX_REPORTED_DIFF_RANGES + 1).err();
        assert!(
            matches!(
                invalid_limit,
                Some(FirmwareError::InvalidDiffRangeLimit { .. })
            ),
            "comparison must bound retained ranges"
        );
    }

    #[test]
    fn candidate_preserves_every_unpatched_byte_and_binds_the_original() {
        let original = b"0123456789";
        let expected_digest = sha256_digest(original);
        let patches = [ImagePatch {
            range: range(3, 6),
            replacement: b"ABC".to_vec(),
        }];

        let candidate = build_candidate(original, &expected_digest, &patches, &[])
            .unwrap_or_else(|error| panic!("candidate must compose: {error}"));

        assert_eq!(
            candidate.as_bytes(),
            b"012ABC6789",
            "only patch bytes may change"
        );
        assert_eq!(candidate.evidence().original_sha256, expected_digest);
        assert_eq!(candidate.evidence().modified_ranges, vec![range(3, 6)]);
    }

    #[test]
    fn candidate_rejects_wrong_base_overlap_bounds_protection_and_length_change() {
        let original = b"0123456789";
        let wrong_base = Sha256Digest::try_from("0".repeat(64)).unwrap_or_else(|error| {
            panic!("digest fixture must be valid: {error}");
        });
        let valid_base = sha256_digest(original);

        let wrong_base_error = build_candidate(original, &wrong_base, &[], &[]).err();
        assert!(
            matches!(
                wrong_base_error,
                Some(FirmwareError::CandidateBaseDigestMismatch { .. })
            ),
            "candidate must bind to its requested base"
        );

        let out_of_bounds = [ImagePatch {
            range: range(9, 11),
            replacement: vec![1, 2],
        }];
        assert!(
            matches!(
                build_candidate(original, &valid_base, &out_of_bounds, &[]).err(),
                Some(FirmwareError::RangeOutOfBounds { .. })
            ),
            "candidate must reject out-of-bounds writes"
        );

        let overlapping = [
            ImagePatch {
                range: range(1, 4),
                replacement: vec![1, 2, 3],
            },
            ImagePatch {
                range: range(3, 5),
                replacement: vec![4, 5],
            },
        ];
        assert!(
            matches!(
                build_candidate(original, &valid_base, &overlapping, &[]).err(),
                Some(FirmwareError::OverlappingPatches { .. })
            ),
            "candidate must reject overlapping writes"
        );

        let protected = [ImagePatch {
            range: range(2, 4),
            replacement: vec![1, 2],
        }];
        assert!(
            matches!(
                build_candidate(original, &valid_base, &protected, &[range(3, 5)]).err(),
                Some(FirmwareError::PatchTouchesProtectedRange { .. })
            ),
            "candidate must preserve protected bytes"
        );

        let wrong_length = [ImagePatch {
            range: range(2, 4),
            replacement: vec![1],
        }];
        assert!(
            matches!(
                build_candidate(original, &valid_base, &wrong_length, &[]).err(),
                Some(FirmwareError::PatchLengthMismatch { .. })
            ),
            "candidate must preserve image length"
        );
    }

    #[test]
    fn range_and_digest_deserialization_route_through_validation() {
        let invalid_range = serde_json::from_value::<ByteRange>(json!({
            "start_byte": 8,
            "end_byte_exclusive": 8,
        }));
        assert!(invalid_range.is_err(), "serde must reject empty ranges");

        let invalid_digest = serde_json::from_value::<Sha256Digest>(json!("A".repeat(64)));
        assert!(
            invalid_digest.is_err(),
            "serde must reject uppercase digest text"
        );
    }
}
