//! Tunnel pump: the real bidirectional data path.
//!
//! Outbound half: reads IP packets from the TUN fd (poll(2)/read(2) — the fd
//! is owned by Android), seals each into a Reality record under the session
//! send key, and writes it as a framed record onto the tunnel socket.
//!
//! Inbound half: reads framed records from the tunnel socket, opens them
//! under the session receive key, and writes the plaintext IP packets into
//! the TUN fd.
//!
//! Sequence numbers are handed in by the session layer so data records
//! continue after any handshake-time probe records without nonce reuse.
//! If either half dies (socket error, EOF, TUN gone), the socket is shut
//! down so the other half exits promptly too.
//!
//! Host-testable end to end against the honest in-process server: no mocks.

use crate::handshake::HandshakeState;
use crate::transport::{read_frame, write_frame};
use std::io::{ErrorKind, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const READ_BUF: usize = 1500;
/// poll(2) timeout for the TUN read loop: short enough that stop() is
/// responsive, long enough to not burn CPU.
const POLL_MS: i32 = 200;

/// Counters surfaced back to Kotlin for the UI / diagnostics.
#[derive(Debug, Default, Clone)]
pub struct PumpStats {
    /// IP packets read from the TUN (outbound).
    pub packets_in: u64,
    /// Reality records written to the socket (outbound, sealed).
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Opened records delivered into the TUN (inbound).
    pub delivered_packets: u64,
    pub delivered_bytes: u64,
    pub seal_errors: u64,
    pub open_errors: u64,
    /// IPv6 packets deliberately blackholed inside the tunnel (leak shield).
    pub dropped_packets: u64,
}

/// Pump behavior knobs.
#[derive(Debug, Clone, Copy)]
pub struct PumpConfig {
    /// Drop (blackhole) all IPv6 packets read from the TUN instead of
    /// sealing them. The pump is the only egress from the TUN, so dropping
    /// here means IPv6 never reaches the underlying network while the VPN
    /// still advertises an IPv6 route to catch that traffic.
    pub block_ipv6: bool,
}

impl Default for PumpConfig {
    fn default() -> Self {
        PumpConfig { block_ipv6: false }
    }
}

/// IP version nibble of an IPv4/IPv6 header.
fn ip_version(buf: &[u8]) -> u8 {
    buf.first().map(|b| b >> 4).unwrap_or(0)
}

/// Block until `fd` is readable or the timeout elapses. Returns true when a
/// subsequent read will not block (including EOF/hangup conditions).
fn wait_readable(fd: RawFd, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    ready > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0
}

/// read(2) wrapper over a raw fd with EINTR retry.
fn read_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Write half over a raw fd using libc write(2). The fd is owned by the
/// caller (Android owns the TUN; host tests own the socketpair).
struct FdWriter {
    fd: RawFd,
}

impl Write for FdWriter {
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

struct TunnelInner {
    running: AtomicBool,
    stop: AtomicBool,
    alive: AtomicUsize,
    stats: Mutex<PumpStats>,
    /// Outbound record sequence (client->server). Strictly increasing; never
    /// reused within the session.
    seq_out: AtomicU64,
    /// Inbound record sequence (server->client).
    seq_in: AtomicU64,
    /// A handle to the tunnel socket used to unblock the inbound half and to
    /// tear the tunnel down when either half dies.
    halt: Mutex<Option<TcpStream>>,
}

impl TunnelInner {
    fn bump(stats: &Mutex<PumpStats>, f: impl Fn(&mut PumpStats)) {
        if let Ok(mut s) = stats.lock() {
            f(&mut s);
        }
    }

    /// Shut the socket down so a blocked read/write on the other half
    /// returns immediately. Idempotent.
    fn halt_socket(&self) {
        if let Ok(mut guard) = self.halt.lock() {
            if let Some(s) = guard.take() {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }

    fn thread_finished(self: &Arc<Self>) {
        if self.alive.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.running.store(false, Ordering::SeqCst);
            self.halt_socket();
        }
    }
}

/// One bidirectional tunnel over one TUN fd and one connected socket.
pub struct TunnelPump {
    inner: Arc<TunnelInner>,
}

impl TunnelPump {
    pub fn new() -> TunnelPump {
        TunnelPump {
            inner: Arc::new(TunnelInner {
                running: AtomicBool::new(false),
                stop: AtomicBool::new(false),
                alive: AtomicUsize::new(0),
                stats: Mutex::new(PumpStats::default()),
                seq_out: AtomicU64::new(0),
                seq_in: AtomicU64::new(0),
                halt: Mutex::new(None),
            }),
        }
    }

    /// Spawn both direction halves. `fd` is the TUN (Android owns and closes
    /// it); `socket` is the established, handshaked tunnel connection.
    /// `next_out_seq` / `next_in_seq` continue the session's record sequences
    /// after handshake-time records.
    pub fn start(
        &self,
        fd: RawFd,
        socket: TcpStream,
        handshake: Arc<HandshakeState>,
        config: PumpConfig,
        next_out_seq: u64,
        next_in_seq: u64,
    ) -> Result<(), String> {
        if self.inner.running.swap(true, Ordering::SeqCst) {
            return Err("tunnel pump already running".to_owned());
        }
        let _ = socket.set_nodelay(true);
        self.inner.stop.store(false, Ordering::SeqCst);
        self.inner.seq_out.store(next_out_seq, Ordering::SeqCst);
        self.inner.seq_in.store(next_in_seq, Ordering::SeqCst);

        // Separate handles: outbound writes on its own clone, inbound reads
        // on the original, and halt(2) can be issued from either half.
        let out_socket = socket
            .try_clone()
            .map_err(|e| format!("socket clone failed: {e}"))?;
        *self.inner.halt.lock().expect("halt mutex") = socket.try_clone().ok();

        let inner = Arc::clone(&self.inner);
        self.inner.alive.store(2, Ordering::SeqCst);

        // ---- outbound: TUN -> seal -> socket ----
        {
            let inner = Arc::clone(&inner);
            let handshake = Arc::clone(&handshake);
            let mut out_socket = out_socket;
            std::thread::spawn(move || {
                loop {
                    if inner.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if !wait_readable(fd, POLL_MS) {
                        continue;
                    }
                    let mut buf = vec![0u8; READ_BUF];
                    match read_fd(fd, &mut buf) {
                        Ok(0) => break, // EOF on TUN fd
                        Ok(n) => {
                            TunnelInner::bump(&inner.stats, |s| {
                                s.packets_in += 1;
                                s.bytes_in += n as u64;
                            });
                            // Leak shield: blackhole IPv6 inside the tunnel.
                            if config.block_ipv6 && ip_version(&buf[..n]) == 6 {
                                TunnelInner::bump(&inner.stats, |s| s.dropped_packets += 1);
                                continue;
                            }
                            let seq = inner.seq_out.fetch_add(1, Ordering::SeqCst);
                            match handshake.seal_record(seq, &buf[..n]) {
                                Ok(sealed) => {
                                    if write_frame(&mut out_socket, &sealed).is_ok() {
                                        TunnelInner::bump(&inner.stats, |s| {
                                            s.packets_out += 1;
                                            s.bytes_out += sealed.len() as u64;
                                        });
                                    } else {
                                        inner.seq_out.fetch_sub(1, Ordering::SeqCst);
                                        inner.halt_socket();
                                        break; // socket gone; inbound half unblocks via halt
                                    }
                                }
                                Err(_) => {
                                    inner.seq_out.fetch_sub(1, Ordering::SeqCst);
                                    TunnelInner::bump(&inner.stats, |s| s.seal_errors += 1);
                                }
                            }
                        }
                        Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                inner.thread_finished();
            });
        }

        // ---- inbound: socket -> open -> TUN ----
        {
            let inner = Arc::clone(&inner);
            let handshake = Arc::clone(&handshake);
            let mut in_socket = socket;
            std::thread::spawn(move || {
                let mut tun = FdWriter { fd };
                loop {
                    if inner.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    match read_frame(&mut in_socket) {
                        Ok(Some(frame)) => {
                            if frame.is_empty() {
                                continue;
                            }
                            let seq = inner.seq_in.fetch_add(1, Ordering::SeqCst);
                            match handshake.open_record(seq, &frame) {
                                Ok(packet) => {
                                    if tun.write_all(&packet).is_ok() {
                                        TunnelInner::bump(&inner.stats, |s| {
                                            s.delivered_packets += 1;
                                            s.delivered_bytes += packet.len() as u64;
                                        });
                                    } else {
                                        inner.seq_in.fetch_sub(1, Ordering::SeqCst);
                                        inner.halt_socket();
                                        break; // TUN gone
                                    }
                                }
                                Err(_) => {
                                    inner.seq_in.fetch_sub(1, Ordering::SeqCst);
                                    TunnelInner::bump(&inner.stats, |s| s.open_errors += 1);
                                }
                            }
                        }
                        Ok(None) => break, // clean EOF from peer
                        Err(_) => break,
                    }
                }
                inner.thread_finished();
            });
        }

        Ok(())
    }

    /// Stop both halves. Shuts the socket down so the inbound read unblocks;
    /// the outbound half observes `stop` within its poll timeout.
    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        self.inner.halt_socket();
    }

    /// False once both halves have exited (or before start). Used by JNI
    /// callers and tests to observe pump liveness.
    #[allow(dead_code)]
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

impl Default for TunnelPump {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, Instant};

    const SERVER_SECRET: [u8; 32] = [7u8; 32];

    /// Establish a real handshaked connection to the honest server.
    fn connect(sni: &str) -> test_server::ClientTunnel {
        test_server::open_tunnel(sni, SERVER_SECRET).expect("wire handshake")
    }

    /// Join the server thread and require it observed an authenticated
    /// session with exactly `records` mirrored client records.
    fn server_saw(
        server: thread::JoinHandle<Result<test_server::ServerObservation, String>>,
        records: u64,
        sni: &str,
    ) {
        let obs = server
            .join()
            .expect("server thread panicked")
            .expect("server session failed");
        assert!(obs.session_authenticated, "session must authenticate");
        assert_eq!(obs.sni, sni, "server must see the SNI from the wire");
        assert_eq!(
            obs.records_mirrored, records,
            "server must have mirrored exactly {records} records"
        );
    }

    fn wait_for_output(sock: &mut UnixStream, timeout: Duration) -> Vec<u8> {
        let deadline = Instant::now() + timeout;
        let mut out = Vec::new();
        while Instant::now() < deadline {
            sock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut tmp = vec![0u8; READ_BUF];
            match sock.read(&mut tmp) {
                Ok(n) if n > 0 => out.extend_from_slice(&tmp[..n]),
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        out
    }

    fn wait_until_stopped(pump: &TunnelPump, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !pump.is_running() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// Full data-plane round trip: IP packet into the TUN side, sealed into
    /// a framed record over the real socket, opened by the honest server,
    /// mirrored back, opened by the pump, delivered back out of the TUN.
    #[test]
    fn tunnel_round_trip_through_honest_server() {
        let tunnel = connect("tunnel.example.com");
        let (tun, mut tun_peer) = UnixStream::pair().expect("socketpair");
        let pump = TunnelPump::new();
        pump.start(
            tun.as_raw_fd(),
            tunnel.socket,
            Arc::clone(&tunnel.state),
            PumpConfig { block_ipv6: false },
            0,
            0,
        )
        .expect("pump start");
        assert!(pump.is_running());

        let payload: Vec<u8> = [0x45u8, 0, 0, 28].iter().copied().chain(0u8..=23).collect();
        tun_peer.write_all(&payload).expect("write packet");
        tun_peer.flush().unwrap();

        let echoed = wait_for_output(&mut tun_peer, Duration::from_secs(5));
        assert_eq!(
            echoed, payload,
            "packet must survive the full tunnel round trip byte-for-byte"
        );

        let stats = pump.stats();
        assert!(stats.packets_in >= 1, "outbound packets must be counted");
        assert!(
            stats.delivered_packets >= 1,
            "inbound delivery must be counted"
        );
        assert_eq!(stats.seal_errors, 0);
        assert_eq!(stats.open_errors, 0);
        assert_eq!(stats.dropped_packets, 0);
        pump.stop();
        assert!(
            wait_until_stopped(&pump, Duration::from_secs(3)),
            "pump must stop after stop()"
        );
        server_saw(tunnel.server, 1, "tunnel.example.com");
    }

    /// Leak shield over the real tunnel: IPv6 must be blackholed inside the
    /// tunnel (never sealed, never sent) while v4 keeps flowing.
    #[test]
    fn ipv6_blackholed_but_ipv4_flows_through_tunnel() {
        let tunnel = connect("leak.example.com");
        let (tun, mut tun_peer) = UnixStream::pair().expect("socketpair");
        let pump = TunnelPump::new();
        pump.start(
            tun.as_raw_fd(),
            tunnel.socket,
            Arc::clone(&tunnel.state),
            PumpConfig { block_ipv6: true },
            0,
            0,
        )
        .expect("pump start");

        // IPv6 packet: version nibble 6.
        let mut v6 = vec![0u8; 48];
        v6[0] = 0x60;
        tun_peer.write_all(&v6).expect("write v6");
        tun_peer.flush().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            pump.stats().dropped_packets,
            1,
            "v6 must be counted as dropped"
        );
        assert_eq!(pump.stats().packets_out, 0, "v6 must never be sealed out");

        // v4 still flows end to end.
        let v4: Vec<u8> = [0x45u8, 0, 0, 20].iter().copied().chain(0u8..=15).collect();
        tun_peer.write_all(&v4).expect("write v4");
        tun_peer.flush().unwrap();
        let echoed = wait_for_output(&mut tun_peer, Duration::from_secs(5));
        assert_eq!(echoed, v4, "v4 must still flow while v6 is blocked");
        assert_eq!(pump.stats().dropped_packets, 1);
        assert_eq!(pump.stats().packets_out, 1);
        pump.stop();
        // Wire truth: the server mirrored exactly ONE record — the v6 packet
        // never reached it. The leak shield is proven end to end.
        server_saw(tunnel.server, 1, "leak.example.com");
    }

    /// Starting a pump twice must be rejected, not silently restarted.
    #[test]
    fn double_start_is_rejected() {
        let tunnel = connect("once.example.com");
        let (tun, _tun_peer) = UnixStream::pair().expect("socketpair");
        let pump = TunnelPump::new();
        let socket_for_second = tunnel.socket.try_clone().expect("socket clone");
        pump.start(
            tun.as_raw_fd(),
            tunnel.socket,
            Arc::clone(&tunnel.state),
            PumpConfig::default(),
            0,
            0,
        )
        .expect("first start");
        let second = pump.start(
            tun.as_raw_fd(),
            socket_for_second,
            Arc::clone(&tunnel.state),
            PumpConfig::default(),
            0,
            0,
        );
        assert!(second.is_err(), "second start must be rejected");
        pump.stop();
    }

    #[test]
    fn stats_default_zeroed() {
        let pump = TunnelPump::new();
        let s = pump.stats();
        assert_eq!(s.packets_in, 0);
        assert_eq!(s.packets_out, 0);
        assert_eq!(s.delivered_packets, 0);
        assert!(!pump.is_running());
    }

    /// Sequence continuation: after a handshake-time probe consumed seq 0 on
    /// both directions, the pump must continue at seq 1. If it restarted at
    /// 0, the honest server (whose counters are already at 1) would fail to
    /// open the record and nothing would come back.
    #[test]
    fn sequences_continue_after_probe_records() {
        let tunnel = connect("seq.example.com");

        // Handshake-time data-plane probe at seq 0, over the live socket.
        let probe = b"shadevpn-dataplane-probe";
        let sealed = tunnel.state.seal_record(0, probe).expect("seal probe");
        {
            let mut w = tunnel.socket.try_clone().expect("socket clone");
            write_frame(&mut w, &sealed).expect("send probe");
        }
        {
            let mut r = tunnel.socket.try_clone().expect("socket clone");
            let echoed = read_frame(&mut r)
                .expect("read echo")
                .expect("echo present");
            let opened = tunnel
                .state
                .open_record(0, &echoed)
                .expect("open probe echo");
            assert_eq!(opened, probe);
        }

        // Start the pump continuing from seq 1 in both directions.
        let (tun, mut tun_peer) = UnixStream::pair().expect("socketpair");
        let pump = TunnelPump::new();
        pump.start(
            tun.as_raw_fd(),
            tunnel.socket,
            Arc::clone(&tunnel.state),
            PumpConfig::default(),
            1,
            1,
        )
        .expect("pump start");

        let payload: Vec<u8> = [0x45u8, 0, 0, 24].iter().copied().chain(0u8..=19).collect();
        tun_peer.write_all(&payload).expect("write packet");
        tun_peer.flush().unwrap();

        let echoed = wait_for_output(&mut tun_peer, Duration::from_secs(5));
        assert_eq!(
            echoed, payload,
            "data must flow after a handshake-time probe consumed seq 0"
        );
        let stats = pump.stats();
        assert_eq!(stats.open_errors, 0, "inbound seq must continue from 1");
        pump.stop();
        // Server counters: 1 probe + 1 data record in, both mirrored.
        server_saw(tunnel.server, 2, "seq.example.com");
    }

    #[test]
    fn ip_version_detects_v4_and_v6() {
        assert_eq!(ip_version(&[0x45, 0, 0]), 4);
        assert_eq!(ip_version(&[0x60, 0, 0]), 6);
        assert_eq!(ip_version(&[]), 0);
    }
}
