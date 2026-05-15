use std::sync::Arc;
use time::OffsetDateTime;

/// Source of "now". Abstracted so tests can inject a fixed clock.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

pub type SharedClock = Arc<dyn Clock>;
