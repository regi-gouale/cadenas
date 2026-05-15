//! In-memory token-bucket rate limiter.
//!
//! Suitable as a default; swap for a Redis-backed implementation in production
//! by providing your own [`RateLimiter`] impl.

use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[async_trait]
pub trait RateLimiter: Send + Sync + 'static {
    /// Returns `true` if the request is allowed, `false` if it should be denied.
    async fn check(&self, key: &str) -> bool;
}

pub struct InMemoryRateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    state: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl InMemoryRateLimiter {
    pub fn new(capacity: u32, per: Duration) -> Self {
        let refill_per_sec = capacity as f64 / per.as_secs_f64().max(0.001);
        Self {
            capacity: capacity as f64,
            refill_per_sec,
            state: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl RateLimiter for InMemoryRateLimiter {
    async fn check(&self, key: &str) -> bool {
        let mut state = self.state.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        let bucket = state.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
