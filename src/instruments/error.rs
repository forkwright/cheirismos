use snafu::Snafu;

/// Failure at an instrument boundary. Callers must preserve this distinction in
/// the durable operation receipt rather than converting it to a synthetic success.
#[derive(Debug, Snafu)]
pub enum InstrumentError {
    #[snafu(display("{action}: {source}"))]
    Io {
        action: &'static str,
        source: std::io::Error,
    },
    #[snafu(display("timed out while {operation}"))]
    Timeout { operation: &'static str },
    #[snafu(display("stream ended while {operation}"))]
    EndOfStream { operation: &'static str },
    #[snafu(display("frame exceeds {limit}-byte limit"))]
    FrameTooLarge { limit: usize },
    #[snafu(display("malformed COBS frame"))]
    MalformedCobs,
    #[snafu(display("malformed response: {detail}"))]
    MalformedResponse { detail: String },
    #[snafu(display("device rejected request: {detail}"))]
    DeviceRejected { detail: String },
    #[snafu(display("expected {expected} response, received {actual}"))]
    UnexpectedResponse {
        expected: &'static str,
        actual: String,
    },
    #[snafu(display("requested {requested} bytes exceeds device limit {limit}"))]
    ProtocolLimit { requested: usize, limit: usize },
    #[snafu(display("invalid Numato relay response {response:?}"))]
    InvalidRelayResponse { response: String },
    #[snafu(display("invalid simulator store: {detail}"))]
    InvalidSimulatorStore { detail: String },
    #[snafu(display("invalid video configuration: {detail}"))]
    InvalidVideoConfiguration { detail: String },
    #[snafu(display("video executable digest mismatch: expected {expected}, observed {actual}"))]
    VideoExecutableDigestMismatch { expected: String, actual: String },
    #[snafu(display("video USB identity mismatch: expected {expected}, observed {actual}"))]
    VideoIdentityMismatch { expected: String, actual: String },
    #[snafu(display("video capture output is not a PNG"))]
    InvalidVideoFrame,
    #[snafu(display("video capture failed: {detail}"))]
    VideoCaptureFailed { detail: String },
}
