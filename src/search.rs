//! Parallel vanity search.
//!
//! Each attempt draws 32 bytes from the operating-system CSPRNG and keeps the
//! draw only when it is a valid secp256k1 scalar. Workers do not share a
//! userspace RNG and do not walk sequential keys. The first match sets an
//! atomic flag. There is no lock in the candidate loop. Invalid scalars are
//! not counted.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::Error;
use crate::secret::SecretBytes;
use crate::zcash::{
    encode_payload, validate_prefix, KeyEngine, PrefixEstimate, SEARCH_COUNTER_HEADROOM,
};

pub const MAX_THREADS: usize = 256;
pub const COUNTER_HEADROOM: u64 = SEARCH_COUNTER_HEADROOM;
const ATTEMPT_CHUNK: u64 = 1024;

/// Stop before `fetch_add` could wrap a `u64` attempt counter.
pub fn counter_would_overflow(current: u64) -> bool {
    current >= u64::MAX.saturating_sub(COUNTER_HEADROOM)
}

pub struct SearchHit {
    pub key: SecretBytes<32>,
    pub address: String,
    pub public_key: [u8; 33],
    pub attempts: u64,
}

impl std::fmt::Debug for SearchHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchHit")
            .field("key", &self.key)
            .field("address", &self.address)
            .field("public_key", &"[public]")
            .field("attempts", &self.attempts)
            .finish()
    }
}

pub fn validate_threads(threads: usize) -> Result<(), Error> {
    if threads == 0 || threads > MAX_THREADS {
        Err(Error::Threads)
    } else {
        Ok(())
    }
}

/// Search until `prefix` matches, `cancel` is set, or a worker fails.
///
/// `progress` receives `(attempts, candidates_per_second)` about once a second.
/// Both numbers are public. A panic or RNG failure in any worker discards a
/// match from another worker.
pub fn search<F>(
    prefix: &str,
    threads: usize,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> Result<SearchHit, Error>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    let estimate = validate_prefix(prefix)?;
    validate_threads(threads)?;

    let attempts = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let overflow = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Zeroizing<[u8; 32]>>();
    let reporter = spawn_reporter(Arc::clone(&attempts), Arc::clone(&cancel), progress);

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let tx = tx.clone();
        let cancel_worker = Arc::clone(&cancel);
        let attempts = Arc::clone(&attempts);
        let failed_worker = Arc::clone(&failed);
        let overflow = Arc::clone(&overflow);
        let estimate = estimate.clone();
        match thread::Builder::new()
            .name("zcash-vanity".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    worker(&estimate, &cancel_worker, &attempts, &overflow, &tx)
                }));
                if !matches!(outcome, Ok(Ok(()))) {
                    failed_worker.store(true, Ordering::Release);
                    cancel_worker.store(true, Ordering::Release);
                }
            }) {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                failed.store(true, Ordering::Release);
                cancel.store(true, Ordering::Release);
                break;
            }
        }
    }
    drop(tx);

    let first = rx.recv();
    cancel.store(true, Ordering::Release);
    join_workers(handles);
    let _ = reporter.join();

    let mut extra = Vec::new();
    while let Ok(more) = rx.try_recv() {
        extra.push(more);
    }

    let total = attempts.load(Ordering::Relaxed);
    if failed.load(Ordering::Acquire) {
        return Err(Error::SearchFailed);
    }
    if overflow.load(Ordering::Acquire) && first.is_err() {
        return Err(Error::SearchFailed);
    }

    let Some(secret) = first.ok() else {
        return Err(Error::Cancelled { attempts: total });
    };
    drop(extra);

    let key = SecretBytes::from_zeroizing(secret);
    let engine = KeyEngine::new()?;
    let candidate = engine
        .candidate(key.as_bytes())
        .map_err(|_| Error::SearchFailed)?;
    let address = encode_payload(&candidate.payload);
    if !address.starts_with(estimate.as_str()) {
        return Err(Error::SearchFailed);
    }
    Ok(SearchHit {
        key,
        address,
        public_key: candidate.public_key,
        attempts: total,
    })
}

fn spawn_reporter<F>(
    attempts: Arc<AtomicU64>,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> JoinHandle<()>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    thread::spawn(move || {
        let mut last_count = 0u64;
        let mut last_report = Instant::now();
        while !cancel.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(50));
            if cancel.load(Ordering::Acquire) {
                break;
            }
            if last_report.elapsed() < Duration::from_secs(1) {
                continue;
            }
            let now = attempts.load(Ordering::Relaxed);
            let elapsed = last_report.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                ((now.saturating_sub(last_count)) as f64 / elapsed) as u64
            } else {
                0
            };
            let _ = catch_unwind(AssertUnwindSafe(|| progress(now, rate)));
            last_count = now;
            last_report = Instant::now();
        }
    })
}

fn join_workers(handles: Vec<JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.join();
    }
}

fn worker(
    estimate: &PrefixEstimate,
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    tx: &Sender<Zeroizing<[u8; 32]>>,
) -> Result<(), Error> {
    let engine = KeyEngine::new()?;
    let mut local = 0u64;
    let result = (|| -> Result<(), Error> {
        loop {
            if cancel.load(Ordering::Acquire) {
                return Ok(());
            }
            let observed = attempts.load(Ordering::Relaxed).saturating_add(local);
            if counter_would_overflow(observed) {
                overflow.store(true, Ordering::Release);
                cancel.store(true, Ordering::Release);
                return Ok(());
            }

            let mut secret = Zeroizing::new([0u8; 32]);
            if getrandom::getrandom(secret.as_mut_slice()).is_err() {
                return Err(Error::Rng);
            }
            let candidate = match engine.candidate(&secret) {
                Ok(candidate) => candidate,
                Err(Error::InvalidKey) => continue,
                Err(err) => return Err(err),
            };
            let in_range = estimate.contains_payload(&candidate.payload);
            local += 1;
            if local >= ATTEMPT_CHUNK {
                attempts.fetch_add(local, Ordering::Relaxed);
                local = 0;
            }
            if in_range {
                let address = encode_payload(&candidate.payload);
                if address.starts_with(estimate.as_str()) {
                    let _ = tx.send(secret);
                    cancel.store(true, Ordering::Release);
                    return Ok(());
                }
            }
        }
    })();
    if local > 0 {
        attempts.fetch_add(local, Ordering::Relaxed);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::COUNTER_HEADROOM;
    use crate::zcash::SEARCH_COUNTER_HEADROOM;

    #[test]
    fn counter_headroom_is_the_prefix_limit() {
        assert_eq!(COUNTER_HEADROOM, SEARCH_COUNTER_HEADROOM);
        assert_eq!(COUNTER_HEADROOM, 1_048_576);
    }
}
