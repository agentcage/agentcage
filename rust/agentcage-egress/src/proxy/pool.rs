//! The process-wide upstream connection pool.
//!
//! Every client connection used to open its own upstream connections, so
//! an agent that runs one `curl` per request paid a TCP and TLS handshake
//! per request. The pool keeps upstream connections across client
//! connections: idle HTTP/1 connections after a complete exchange, and
//! HTTP/2 sessions, whose streams any client's requests share.
//!
//! A connection is only ever reused for a request that would have opened
//! an identical one ([`UpstreamKey`]: direction, scheme, host, port, SNI,
//! the ALPN offer and the config epoch), and only when the handler's peer
//! guard, asked again at the moment of reuse, still accepts the address the
//! connection actually reached ([`super::FlowHandler::may_reuse`]). So a
//! pooled connection carries nothing a fresh one would not: the same TLS
//! identity, verified against the same name, to an address vetted under
//! today's rules.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, ReadBuf};

use super::ListenerKind;
use super::io::Buffered;

/// How long an unused connection is kept.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Idle HTTP/1 connections kept per key.
pub(crate) const MAX_IDLE_PER_KEY: usize = 16;
/// HTTP/2 sessions kept per key; a new one is only opened when every kept
/// one is at the server's stream limit.
pub(crate) const MAX_H2_PER_KEY: usize = 4;
/// Pooled connections (idle HTTP/1 plus HTTP/2 sessions) kept in all.
pub(crate) const MAX_POOLED: usize = 256;

/// What an upstream connection was opened for; only a request that would
/// open an identical connection may reuse it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct UpstreamKey {
    /// From a reverse listener (to the cage) rather than out of it.
    pub(crate) inbound: bool,
    /// Over TLS.
    pub(crate) tls: bool,
    /// The host dialled (a name, or an address literal).
    pub(crate) host: String,
    /// The port dialled.
    pub(crate) port: u16,
    /// The SNI sent and the name the certificate was verified against.
    pub(crate) sni: Option<String>,
    /// The ALPN protocols offered.
    pub(crate) alpn: Vec<Vec<u8>>,
    /// The handler's config epoch when it was opened.
    pub(crate) epoch: u64,
}

impl UpstreamKey {
    pub(crate) fn inbound(listener: ListenerKind) -> bool {
        listener == ListenerKind::Reverse
    }
}

/// Bounds and timeouts; [`PoolLimits::default`] in production, smaller
/// in tests.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PoolLimits {
    pub(crate) idle_timeout: Duration,
    pub(crate) idle_per_key: usize,
    pub(crate) h2_per_key: usize,
    pub(crate) total: usize,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            idle_timeout: IDLE_TIMEOUT,
            idle_per_key: MAX_IDLE_PER_KEY,
            h2_per_key: MAX_H2_PER_KEY,
            total: MAX_POOLED,
        }
    }
}

struct IdleH1 {
    conn: Buffered,
    peer: IpAddr,
    since: Instant,
}

struct H2Session {
    sender: h2::client::SendRequest<Bytes>,
    peer: IpAddr,
    last_used: Instant,
    /// Streams in flight on it (one per live [`H2Lease`]).
    active: Arc<AtomicUsize>,
}

impl H2Session {
    /// The connection has failed or been told to go away.
    fn is_closed(&self) -> bool {
        let mut probe = self.sender.clone();
        let mut cx = Context::from_waker(Waker::noop());
        matches!(probe.poll_ready(&mut cx), Poll::Ready(Err(_)))
    }

    /// Every stream the server allows is in use.
    fn is_full(&self) -> bool {
        self.active.load(Ordering::Relaxed) >= self.sender.current_max_send_streams().max(1)
    }
}

/// One stream's use of a pooled HTTP/2 session; dropping it frees the slot.
pub(crate) struct H2Lease {
    pub(crate) sender: h2::client::SendRequest<Bytes>,
    active: Arc<AtomicUsize>,
}

impl Drop for H2Lease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl H2Lease {
    fn new(sender: h2::client::SendRequest<Bytes>, active: &Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self {
            sender,
            active: Arc::clone(active),
        }
    }
}

#[derive(Default)]
struct Inner {
    epoch: u64,
    h1: HashMap<UpstreamKey, Vec<IdleH1>>,
    h2: HashMap<UpstreamKey, Vec<H2Session>>,
    /// Idle HTTP/1 connections plus HTTP/2 sessions.
    count: usize,
}

impl Inner {
    /// A key from a newer epoch empties the pool (a reload changed what
    /// upstream selection depends on); one from an older epoch is stale.
    fn admit(&mut self, epoch: u64) -> bool {
        if epoch > self.epoch {
            self.h1.clear();
            self.h2.clear();
            self.count = 0;
            self.epoch = epoch;
        }
        epoch == self.epoch
    }

    fn sweep(&mut self, now: Instant, idle_timeout: Duration) {
        let mut dropped = 0;
        self.h1.retain(|_, idle| {
            let before = idle.len();
            idle.retain(|c| now.duration_since(c.since) < idle_timeout);
            dropped += before - idle.len();
            !idle.is_empty()
        });
        self.h2.retain(|_, sessions| {
            let before = sessions.len();
            sessions.retain(|s| {
                let busy = s.active.load(Ordering::Relaxed) > 0;
                (busy || now.duration_since(s.last_used) < idle_timeout) && !s.is_closed()
            });
            dropped += before - sessions.len();
            !sessions.is_empty()
        });
        self.count -= dropped;
    }
}

/// The pool; one per proxy, shared by every connection task.
pub(crate) struct UpstreamPool {
    inner: Mutex<Inner>,
    limits: PoolLimits,
}

impl std::fmt::Debug for UpstreamPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamPool")
            .field("pooled", &self.lock().count)
            .finish_non_exhaustive()
    }
}

impl Default for UpstreamPool {
    fn default() -> Self {
        Self::new(PoolLimits::default())
    }
}

impl UpstreamPool {
    pub(crate) fn new(limits: PoolLimits) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            limits,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Nothing here can panic half-way through an update that matters:
        // the worst a poisoned pool holds is a connection too many.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A stream slot on a pooled HTTP/2 session for `key` whose peer
    /// `vet` accepts. `None` when there is none, or when every one is at
    /// its stream limit and another may still be opened.
    pub(crate) fn h2(&self, key: &UpstreamKey, vet: impl Fn(IpAddr) -> bool) -> Option<H2Lease> {
        let (lease, peer) = {
            let mut inner = self.lock();
            if !inner.admit(key.epoch) {
                return None;
            }
            let sessions = inner.h2.get_mut(key)?;
            let mut closed = 0;
            sessions.retain(|s| {
                let keep = !s.is_closed();
                closed += usize::from(!keep);
                keep
            });
            let at_cap = sessions.len() >= self.limits.h2_per_key;
            let chosen = sessions
                .iter_mut()
                .filter(|s| at_cap || !s.is_full())
                .min_by_key(|s| s.active.load(Ordering::Relaxed));
            let picked = chosen.map(|s| {
                s.last_used = Instant::now();
                (H2Lease::new(s.sender.clone(), &s.active), s.peer)
            });
            if sessions.is_empty() {
                inner.h2.remove(key);
            }
            inner.count -= closed;
            picked?
        };
        // Outside the lock: the handler's check is its own business.
        if vet(peer) {
            return Some(lease);
        }
        self.forget_h2(key, &lease);
        None
    }

    /// Keep a newly opened HTTP/2 session for `key` (unless the pool is
    /// full), and take its first stream slot.
    pub(crate) fn put_h2(
        &self,
        key: &UpstreamKey,
        sender: h2::client::SendRequest<Bytes>,
        peer: IpAddr,
    ) -> H2Lease {
        let active = Arc::new(AtomicUsize::new(0));
        let lease = H2Lease::new(sender.clone(), &active);
        let mut inner = self.lock();
        if !inner.admit(key.epoch) {
            return lease;
        }
        if inner.count >= self.limits.total {
            inner.sweep(Instant::now(), self.limits.idle_timeout);
        }
        let room = inner.count < self.limits.total;
        let sessions = inner.h2.entry(key.clone()).or_default();
        if room && sessions.len() < self.limits.h2_per_key {
            sessions.push(H2Session {
                sender,
                peer,
                last_used: Instant::now(),
                active,
            });
            inner.count += 1;
        } else if sessions.is_empty() {
            inner.h2.remove(key);
        }
        lease
    }

    /// Stop handing out the session `lease` is on (it failed); streams
    /// already on it finish undisturbed.
    pub(crate) fn forget_h2(&self, key: &UpstreamKey, lease: &H2Lease) {
        let mut inner = self.lock();
        let Some(sessions) = inner.h2.get_mut(key) else {
            return;
        };
        let before = sessions.len();
        sessions.retain(|s| !Arc::ptr_eq(&s.active, &lease.active));
        let removed = before - sessions.len();
        if sessions.is_empty() {
            inner.h2.remove(key);
        }
        inner.count -= removed;
    }

    /// An idle HTTP/1 connection for `key` whose peer `vet` accepts, most
    /// recently used first. Connections that went bad while idle (closed
    /// by the server, or holding bytes nobody asked for) are dropped on
    /// the way.
    pub(crate) fn take_h1(
        &self,
        key: &UpstreamKey,
        vet: impl Fn(IpAddr) -> bool,
    ) -> Option<(Buffered, IpAddr)> {
        loop {
            let mut idle = {
                let mut inner = self.lock();
                if !inner.admit(key.epoch) {
                    return None;
                }
                let conns = inner.h1.get_mut(key)?;
                let idle = conns.pop();
                if conns.is_empty() {
                    inner.h1.remove(key);
                }
                let idle = idle?;
                inner.count -= 1;
                idle
            };
            if idle.since.elapsed() < self.limits.idle_timeout
                && still_idle(&mut idle.conn)
                && vet(idle.peer)
            {
                return Some((idle.conn, idle.peer));
            }
        }
    }

    /// Keep an HTTP/1 connection whose last exchange is complete.
    pub(crate) fn put_h1(&self, key: &UpstreamKey, conn: Buffered, peer: IpAddr) {
        if !conn.buf.is_empty() {
            // The server sent more than the response: whatever it is, it
            // must never be read as the next request's response.
            return;
        }
        let mut inner = self.lock();
        if !inner.admit(key.epoch) {
            return;
        }
        if inner.count >= self.limits.total {
            inner.sweep(Instant::now(), self.limits.idle_timeout);
            if inner.count >= self.limits.total {
                return;
            }
        }
        let per_key = self.limits.idle_per_key;
        let conns = inner.h1.entry(key.clone()).or_default();
        let evicted = if conns.len() >= per_key {
            conns.remove(0);
            1
        } else {
            0
        };
        conns.push(IdleH1 {
            conn,
            peer,
            since: Instant::now(),
        });
        inner.count = inner.count + 1 - evicted;
    }

    /// Drop expired idle connections and dead sessions.
    pub(crate) fn sweep(&self) {
        self.lock().sweep(Instant::now(), self.limits.idle_timeout);
    }

    /// Pooled connections (idle HTTP/1 plus HTTP/2 sessions).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().count
    }
}

/// Whether an idle connection is still quietly open: a read that would
/// block. End of stream, an error, or unsolicited bytes all mean it must
/// not carry another request. (TLS records with no application data, such
/// as late session tickets, are consumed by the TLS layer and still read
/// as "would block".)
fn still_idle(conn: &mut Buffered) -> bool {
    let mut byte = [0u8; 1];
    let mut buf = ReadBuf::new(&mut byte);
    let mut cx = Context::from_waker(Waker::noop());
    Pin::new(&mut conn.io)
        .poll_read(&mut cx, &mut buf)
        .is_pending()
}

/// Sweep `pool` periodically until it is gone.
pub(crate) async fn reap(pool: std::sync::Weak<UpstreamPool>) {
    let mut tick = tokio::time::interval(IDLE_TIMEOUT / 4);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let Some(pool) = pool.upgrade() else { return };
        pool.sweep();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    fn key(host: &str, sni: Option<&str>) -> UpstreamKey {
        UpstreamKey {
            inbound: false,
            tls: true,
            host: host.into(),
            port: 443,
            sni: sni.map(Into::into),
            alpn: vec![b"http/1.1".to_vec()],
            epoch: 0,
        }
    }

    const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    /// An idle connection and the far end that keeps it open.
    fn conn() -> (Buffered, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(64);
        (Buffered::new(Box::new(a)), b)
    }

    fn any(_: IpAddr) -> bool {
        true
    }

    #[tokio::test]
    async fn an_idle_connection_is_reused_for_the_same_key_only() {
        let pool = UpstreamPool::default();
        let k = key("example.com", Some("example.com"));
        let (c, _far) = conn();
        pool.put_h1(&k, c, PEER);
        assert_eq!(pool.len(), 1);
        // Another SNI, another port, another ALPN offer, the other
        // direction, plain instead of TLS: none of them is this connection.
        let mut others = vec![
            key("example.com", Some("other.example")),
            key("example.com", None),
            key("other.example", Some("example.com")),
        ];
        let mut k2 = k.clone();
        k2.port = 8443;
        others.push(k2);
        let mut k3 = k.clone();
        k3.alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        others.push(k3);
        let mut k4 = k.clone();
        k4.inbound = true;
        others.push(k4);
        let mut k5 = k.clone();
        k5.tls = false;
        others.push(k5);
        for other in &others {
            assert!(pool.take_h1(other, any).is_none(), "{other:?}");
        }
        let (_, peer) = pool.take_h1(&k, any).expect("same key reuses");
        assert_eq!(peer, PEER);
        assert_eq!(pool.len(), 0);
        assert!(pool.take_h1(&k, any).is_none(), "handed out once");
    }

    #[tokio::test]
    async fn a_peer_the_guard_now_refuses_is_not_reused() {
        let pool = UpstreamPool::default();
        let k = key("example.com", Some("example.com"));
        let (c, _far) = conn();
        pool.put_h1(&k, c, PEER);
        assert!(pool.take_h1(&k, |ip| ip != PEER).is_none());
        // Refused means dropped, not kept for later.
        assert_eq!(pool.len(), 0);
        assert!(pool.take_h1(&k, any).is_none());
    }

    #[tokio::test]
    async fn connections_expire_and_a_newer_epoch_empties_the_pool() {
        let pool = UpstreamPool::new(PoolLimits {
            idle_timeout: Duration::from_millis(30),
            ..PoolLimits::default()
        });
        let k = key("example.com", Some("example.com"));
        let (c, _far) = conn();
        pool.put_h1(&k, c, PEER);
        tokio::time::sleep(Duration::from_millis(60)).await;
        pool.sweep();
        assert_eq!(pool.len(), 0, "expired by the sweep");
        let (c, _far2) = conn();
        pool.put_h1(&k, c, PEER);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(pool.take_h1(&k, any).is_none(), "expired at checkout");

        let pool = UpstreamPool::default();
        let (c, _far3) = conn();
        pool.put_h1(&k, c, PEER);
        let mut reloaded = k.clone();
        reloaded.epoch = 1;
        assert!(pool.take_h1(&reloaded, any).is_none());
        assert_eq!(pool.len(), 0, "the reload dropped what was pooled");
        // A connection opened before the reload comes back too late.
        let (c, _far4) = conn();
        pool.put_h1(&k, c, PEER);
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn closed_or_chatty_connections_are_not_reused() {
        let pool = UpstreamPool::default();
        let k = key("example.com", Some("example.com"));
        let (c, far) = conn();
        pool.put_h1(&k, c, PEER);
        drop(far);
        assert!(pool.take_h1(&k, any).is_none(), "closed while idle");

        let (c, mut far) = conn();
        pool.put_h1(&k, c, PEER);
        far.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        assert!(pool.take_h1(&k, any).is_none(), "bytes nobody asked for");

        let (mut c, _far) = conn();
        c.buf.extend_from_slice(b"leftover");
        pool.put_h1(&k, c, PEER);
        assert_eq!(pool.len(), 0, "never pooled with unread bytes");
    }

    #[tokio::test]
    async fn the_caps_hold() {
        let pool = UpstreamPool::new(PoolLimits {
            idle_per_key: 2,
            total: 3,
            ..PoolLimits::default()
        });
        let a = key("a.example", Some("a.example"));
        let b = key("b.example", Some("b.example"));
        let mut far = Vec::new();
        for _ in 0..3 {
            let (c, f) = conn();
            far.push(f);
            pool.put_h1(&a, c, PEER);
        }
        assert_eq!(pool.len(), 2, "per-key cap");
        for _ in 0..3 {
            let (c, f) = conn();
            far.push(f);
            pool.put_h1(&b, c, PEER);
        }
        assert_eq!(pool.len(), 3, "global cap");
    }

    /// An HTTP/2 session to an in-memory server that accepts and holds
    /// streams.
    async fn h2_session(max_streams: u32) -> h2::client::SendRequest<Bytes> {
        let (client, server) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .max_concurrent_streams(max_streams)
                .handshake::<_, Bytes>(server)
                .await
                .unwrap();
            let mut held = Vec::new();
            while let Some(Ok(stream)) = conn.accept().await {
                held.push(stream);
            }
        });
        let (sender, connection) = h2::client::handshake(client).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        // Let the server's SETTINGS arrive.
        let sender = sender.ready().await.unwrap();
        let req = http::Request::get("https://example.com/").body(()).unwrap();
        let mut probe = sender.clone();
        let _ = probe.send_request(req, true).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        sender
    }

    #[tokio::test]
    async fn h2_sessions_are_shared_until_full_then_another_is_opened() {
        let pool = UpstreamPool::default();
        let k = key("example.com", Some("example.com"));
        assert!(pool.h2(&k, any).is_none());
        let first = pool.put_h2(&k, h2_session(2).await, PEER);
        // Another client's request: same session, the second stream.
        let second = pool.h2(&k, any).expect("shared");
        assert!(Arc::ptr_eq(&first.active, &second.active));
        // Full at two streams: the caller should open another.
        assert!(pool.h2(&k, any).is_none());
        let third = pool.put_h2(&k, h2_session(2).await, PEER);
        assert!(!Arc::ptr_eq(&first.active, &third.active));
        assert_eq!(pool.len(), 2);
        // A stream finishing frees a slot on the first session.
        drop(second);
        let again = pool.h2(&k, any).expect("slot free again");
        assert!(Arc::ptr_eq(&first.active, &again.active));
        // Another SNI never shares it, and a refused peer is forgotten.
        assert!(
            pool.h2(&key("example.com", Some("other.example")), any)
                .is_none()
        );
        drop(again);
        drop(third);
        assert!(pool.h2(&k, |_| false).is_none());
        assert_eq!(pool.len(), 1);
        pool.forget_h2(&k, &first);
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn idle_h2_sessions_expire_but_busy_ones_stay() {
        let pool = UpstreamPool::new(PoolLimits {
            idle_timeout: Duration::from_millis(30),
            ..PoolLimits::default()
        });
        let k = key("example.com", Some("example.com"));
        let busy = pool.put_h2(&k, h2_session(10).await, PEER);
        tokio::time::sleep(Duration::from_millis(60)).await;
        pool.sweep();
        assert_eq!(pool.len(), 1, "a stream is still on it");
        drop(busy);
        pool.sweep();
        assert_eq!(pool.len(), 0);
    }
}
