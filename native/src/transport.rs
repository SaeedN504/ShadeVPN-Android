//! Wire transport: length-prefixed Reality record frames over TCP.
//!
//! Every record on the socket is framed as [u32 BE length][payload] so the
//! pump and the server can re-synchronize record boundaries reliably. The
//! maximum frame size bounds memory use against a hostile peer.

use std::io::{Read, Write};

pub const MAX_FRAME_LEN: u32 = 70_000; // 65_535 max IP packet + overhead

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    /// Peer announced a frame larger than we accept.
    TooLarge(u32),
    /// Socket closed mid-frame.
    ClosedMidFrame,
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "frame i/o error: {e}"),
            FrameError::TooLarge(n) => write!(f, "frame length {n} exceeds limit"),
            FrameError::ClosedMidFrame => write!(f, "connection closed mid-frame"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Write one framed record: 4-byte big-endian length prefix, then payload.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Read one framed record. Returns Ok(None) on a clean EOF at a frame
/// boundary (peer closed down gracefully).
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)
        .map_err(|_| FrameError::ClosedMidFrame)?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::net::UnixStream;

    #[test]
    fn frame_round_trips_in_memory() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello world").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut cursor = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut cursor).unwrap(),
            Some(b"hello world".to_vec())
        );
        assert_eq!(read_frame(&mut cursor).unwrap(), Some(Vec::new()));
        assert_eq!(read_frame(&mut cursor).unwrap(), None);
    }

    #[test]
    fn frames_through_a_real_socket_pair() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        write_frame(&mut a, &[0x45u8; 1400]).unwrap();
        write_frame(&mut a, b"second").unwrap();
        let got1 = read_frame(&mut b).unwrap().unwrap();
        let got2 = read_frame(&mut b).unwrap().unwrap();
        assert_eq!(got1, vec![0x45u8; 1400]);
        assert_eq!(got2, b"second".to_vec());
    }

    #[test]
    fn oversized_frame_length_is_rejected_on_read() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            read_frame(&mut cursor),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn oversized_payload_is_rejected_on_write() {
        let mut sink = Vec::new();
        let big = vec![0u8; MAX_FRAME_LEN as usize + 1];
        assert!(matches!(
            write_frame(&mut sink, &big),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn clean_eof_at_boundary_is_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_frame(&mut cursor).unwrap(), None);
    }

    #[test]
    fn truncated_payload_is_detected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(b"short");
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            read_frame(&mut cursor),
            Err(FrameError::ClosedMidFrame)
        ));
    }
}
