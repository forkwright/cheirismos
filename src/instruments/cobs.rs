use tokio::io::{AsyncRead, AsyncReadExt};

use super::InstrumentError;

pub(crate) const FRAME_DELIMITER: u8 = 0;

pub(crate) fn encode(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + (payload.len() / 254) + 2);
    let mut block = Vec::with_capacity(usize::from(u8::MAX - 1));

    for &byte in payload {
        if byte == FRAME_DELIMITER {
            append_block(&mut frame, &block);
            block.clear();
        } else {
            block.push(byte);
            if block.len() == usize::from(u8::MAX - 1) {
                append_block(&mut frame, &block);
                block.clear();
            }
        }
    }
    append_block(&mut frame, &block);
    frame.push(FRAME_DELIMITER);
    frame
}

fn append_block(frame: &mut Vec<u8>, block: &[u8]) {
    // `encode` flushes at 254 data bytes, so this conversion is bounded by 255.
    frame.push((block.len() + 1) as u8);
    frame.extend_from_slice(block);
}

pub(crate) fn decode(frame: &[u8], limit: usize) -> Result<Vec<u8>, InstrumentError> {
    if frame.is_empty() || frame.len() > limit {
        return Err(InstrumentError::FrameTooLarge { limit });
    }

    let mut decoded = Vec::with_capacity(frame.len());
    let mut remaining = frame;
    while let Some((&code_byte, after_code)) = remaining.split_first() {
        let code = usize::from(code_byte);
        if code == 0 {
            return Err(InstrumentError::MalformedCobs);
        }
        let payload_length = code - 1;
        let block = after_code
            .get(..payload_length)
            .ok_or(InstrumentError::MalformedCobs)?;
        decoded.extend_from_slice(block);
        remaining = after_code
            .get(payload_length..)
            .ok_or(InstrumentError::MalformedCobs)?;
        if code != usize::from(u8::MAX) && !remaining.is_empty() {
            decoded.push(FRAME_DELIMITER);
        }
        if decoded.len() > limit {
            return Err(InstrumentError::FrameTooLarge { limit });
        }
    }
    Ok(decoded)
}

pub(crate) async fn read_delimited<T>(
    stream: &mut T,
    limit: usize,
    operation: &'static str,
) -> Result<Vec<u8>, InstrumentError>
where
    T: AsyncRead + Unpin,
{
    let mut encoded = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let count = stream
            .read(&mut byte)
            .await
            .map_err(|source| InstrumentError::Io {
                action: "reading instrument frame",
                source,
            })?;
        if count == 0 {
            return Err(InstrumentError::EndOfStream { operation });
        }
        let byte = byte
            .first()
            .copied()
            .ok_or(InstrumentError::EndOfStream { operation })?;
        if byte == FRAME_DELIMITER {
            return decode(&encoded, limit);
        }
        encoded.push(byte);
        if encoded.len() > limit {
            return Err(InstrumentError::FrameTooLarge { limit });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use crate::instruments::InstrumentError;

    #[test]
    fn round_trips_zeroes_and_long_blocks() {
        let payload = (0u16..600)
            .map(|value| u8::try_from(value % 251).unwrap_or_default())
            .collect::<Vec<_>>();
        let encoded = encode(&payload);
        let decoded = decode(&encoded[..encoded.len() - 1], 1024).unwrap_or_default();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rejects_truncated_cobs_block() {
        assert!(matches!(
            decode(&[3, 0xAA], 32),
            Err(InstrumentError::MalformedCobs)
        ));
    }
}
