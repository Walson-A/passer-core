//! Rate limits: how often something may happen, per key.
//!
//! A token bucket per key: `burst` tokens to start with, refilled at `per_minute`. Keys
//! that have been idle long enough to be full again are forgotten, so the table cannot
//! grow without bound; past `max_keys`, new keys are refused until room frees up.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Instant;

/// A token-bucket rate limiter keyed by `K` (a device id, an address...).
pub struct RateLimiter<K> {
    per_sec: f64,
    burst: f64,
    max_keys: usize,
    buckets: Mutex<HashMap<K, (f64, Instant)>>,
}

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    /// Allows `burst` events at once (at least 1), refilled at `per_minute`, tracking at
    /// most `max_keys` keys.
    pub fn new(per_minute: u32, burst: u32, max_keys: usize) -> Self {
        Self {
            per_sec: f64::from(per_minute) / 60.0,
            burst: f64::from(burst.max(1)),
            max_keys,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one token for `key`; `false` if there is none left.
    pub fn allow(&self, key: &K) -> bool {
        self.allow_at(key, Instant::now())
    }

    /// Whether `key` has a token left, without taking it (to spend one only on failure).
    pub fn has_token(&self, key: &K) -> bool {
        let now = Instant::now();
        let buckets = self.buckets.lock().expect("limiter lock");
        match buckets.get(key) {
            Some((tokens, at)) => {
                tokens + now.duration_since(*at).as_secs_f64() * self.per_sec >= 1.0
            }
            None => buckets.len() < self.max_keys,
        }
    }

    fn allow_at(&self, key: &K, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().expect("limiter lock");
        if !buckets.contains_key(key) && buckets.len() >= self.max_keys {
            let (per_sec, burst) = (self.per_sec, self.burst);
            buckets.retain(|_, (tokens, at)| {
                *tokens + now.duration_since(*at).as_secs_f64() * per_sec < burst
            });
            if buckets.len() >= self.max_keys {
                return false;
            }
        }
        let (tokens, at) = buckets.entry(key.clone()).or_insert((self.burst, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * self.per_sec).min(self.burst);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bursts_then_refills() {
        let l = RateLimiter::new(60, 3, 100);
        let t0 = Instant::now();
        assert!((0..3).all(|_| l.allow_at(&"a", t0)));
        assert!(!l.allow_at(&"a", t0), "burst spent");
        assert!(l.allow_at(&"b", t0), "keys are independent");
        assert!(
            l.allow_at(&"a", t0 + Duration::from_secs(1)),
            "one per second comes back"
        );
        assert!(!l.allow_at(&"a", t0 + Duration::from_secs(1)));
    }

    #[test]
    fn the_table_stays_bounded() {
        let l = RateLimiter::new(60, 1, 2);
        let t0 = Instant::now();
        assert!(l.allow_at(&1, t0));
        assert!(l.allow_at(&2, t0));
        assert!(!l.allow_at(&3, t0), "full, and nobody is idle yet");
        // After a second, key 1's bucket is full again: it is forgotten for key 3.
        assert!(l.allow_at(&3, t0 + Duration::from_secs(2)));
    }
}
