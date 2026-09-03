//! Packet pump: reads IP packets from a file descriptor (the Android TUN fd
//! handed over JNI), seals each into a Reality record, and writes sealed
//! frames back to the same fd. The fd is owned by Android; this module only
//! ever read(2)/write(2)s it.
//!
//! Designed so the round-trip is testable on any host OS with an ordinary
//! socketpair-style fd pair — no Android device required.

use crate::handshake::HandshakeState;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const MAX_PACKET: usize = 65535;
const READ_BUF: usize = 1500;

/// Counters surfaced back to Kotlin for the UI / diagnostics.
#[derive(Debug, Default, Clone)]
pub struct PumpStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub seal_errors: u64,
    pub open_errors: u64,
}

struct Inner {
    running: AtomicBool,
    stop: AtomicBool,
    stats: Mutex<PumpStats>,
}

impl Inner {
    fn bump(stats: &Mutex<PumpStats>, f: impl Fn(&mut PumpStats)) {
        if let Ok(mut s) = stats.lock() {
            f(&mut s);
        }
    }
}

/// A pump bound to one TUN fd and one completed handshake.
pub struct PacketPump {
    inner: Arc<Inner>,
}

impl PacketPump {
    pub fn new() -> PacketPump {
        PacketPump {
            inner: Arc::new(Inner {
                running: AtomicBool::new(false),
                stop: AtomicBool::new(false),
                stats: Mutex::new(PumpStats::default()),
            }),
        }
    }

    /// Spawn the pump on a background thread. Returns immediately.
    /// `fd` must remain valid for the pump's lifetime; the caller (Android)
    /// owns and closes it.
    pub fn start(&self, fd: RawFd, handshake: Arc<HandshakeState>) {
        if self.inner.running.swap(true, Ordering::SeqCst) {
            return; // already running
        }
        self.inner.stop.store(false, Ordering::SeqCst);
        let inner = Arc::clone(&self.inner);
        std::thread::spawn(move || {
            let mut source = FdStream::read_side(fd);
            let mut sink = FdStream::write_side(fd);
            loop {
                if inner.stop.load(Ordering::SeqCst) {
                    break;
                }
                let mut buf = vec![0u8; READ_BUF];
                match source.read(&mut buf) {
                    Ok(0) => break, // EOF on TUN fd
                    Ok(n) => {
                        Inner::bump(&inner.stats, |s| {
                            s.packets_in += 1;
                            s.bytes_in += n as u64;
                        });
                        match handshake.seal_record(seq_from(&inner), &buf[..n]) {
                            Ok(sealed) => {
                                if sink.write_all(&sealed).is_ok() {
                                    Inner::bump(&inner.stats, |s| {
                                        s.packets_out += 1;
                                        s.bytes_out += sealed.len() as u64;
                                    });
                                }
                            }
                            Err(_) => Inner::bump(&inner.stats, |s| s.seal_errors += 1),
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            inner.running.store(false, Ordering::SeqCst);
        });
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::SeqCst)
    }

    pub fn stats(&self) -> PumpStats {
        self.inner
            .stats
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }
}

impl Default for PacketPump {
    fn default() -> Self {
        Self::new()
    }
}

fn seq_from(_inner: &Inner) -> u64 {
    // Per-record sequence derived from outbound counter; monotonic, never reused.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::SeqCst)
}

/// Read/write halves over a raw fd using libc read(2)/write(2). Split so the
/// pump can hold both without a mutable borrow conflict. Works with any
/// blocking fd — TUN on Android, or a socketpair fd in host tests.
struct FdStream {
    fd: RawFd,
}

impl FdStream {
    fn read_side(fd: RawFd) -> Self {
        FdStream { fd }
    }
    fn write_side(fd: RawFd) -> Self {
        FdStream { fd }
    }
}

impl Read for FdStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let n =
                unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

impl Write for FdStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{HandshakeParams, HandshakeState};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn test_handshake() -> Arc<HandshakeState> {
        use x25519_dalek::{PublicKey, StaticSecret};
        let server_secret = StaticSecret::from([7u8; 32]);
        let params = HandshakeParams {
            server_address: "127.0.0.1".into(),
            server_port: 443,
            sni: "test.example.com".into(),
            server_public_key: *PublicKey::from(&server_secret).as_bytes(),
            short_id: vec![0x01, 0x02],
            fingerprint: None,
        };
        Arc::new(HandshakeState::initiate(&params).expect("handshake"))
    }

    /// The milestone 3 headline test: real bytes in through one fd, sealed,
    /// written back out through the paired fd, and opened — a full round trip
    /// through a real fd pair, no mocks.
    #[test]
    fn packet_round_trip_through_real_fds() {
        let (sock_a, mut sock_b) = UnixStream::pair().expect("socketpair");
        let handshake = test_handshake();
        let pump = PacketPump::new();
        let fd_a = sock_a.as_raw_fd();
        pump.start(fd_a, Arc::clone(&handshake));
        assert!(pump.is_running());

        // Write an "IP packet" into the peer end; the pump reads it from fd_a.
        let payload: Vec<u8> = (0u8..=200).cycle().take(512).collect();
        sock_b.write_all(&payload).expect("write payload");
        sock_b.flush().unwrap();

        // Give the pump a moment to seal + echo.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut sealed = Vec::new();
        while std::time::Instant::now() < deadline {
            sock_b
                .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                .unwrap();
            let mut tmp = vec![0u8; MAX_PACKET];
            match sock_b.read(&mut tmp) {
                Ok(n) if n > 0 => {
                    sealed.extend_from_slice(&tmp[..n]);
                    if !sealed.is_empty() {
                        break;
                    }
                }
                _ => continue,
            }
        }
        assert!(!sealed.is_empty(), "pump never echoed sealed data");

        // Open the sealed record — must recover the original payload.
        let opened = handshake
            .open_local_record(0, &sealed)
            .expect("open sealed record");
        assert_eq!(opened, payload);

        pump.stop();
        let stats = pump.stats();
        assert!(
            stats.packets_in >= 1,
            "packets_in should count, got {:?}",
            stats
        );
        assert!(
            stats.packets_out >= 1,
            "packets_out should count, got {:?}",
            stats
        );
        assert_eq!(stats.seal_errors, 0);
    }

    #[test]
    fn stats_default_zeroed() {
        let pump = PacketPump::new();
        let s = pump.stats();
        assert_eq!(s.packets_in, 0);
        assert_eq!(s.packets_out, 0);
        assert!(!pump.is_running());
    }

    #[test]
    fn double_start_is_noop() {
        let pump = PacketPump::new();
        let (sock_a, _sock_b) = UnixStream::pair().expect("socketpair");
        let handshake = test_handshake();
        pump.start(sock_a.as_raw_fd(), Arc::clone(&handshake));
        let first_running = pump.is_running();
        pump.start(sock_a.as_raw_fd(), handshake); // second call is a no-op
        assert!(first_running);
        pump.stop();
    }
}
