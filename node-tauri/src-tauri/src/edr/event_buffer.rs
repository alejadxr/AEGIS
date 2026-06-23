// ---------------------------------------------------------------------------
// Lock-free(ish) ring buffer for EDR events (Task #5)
//
// Bounded VecDeque protected by the enclosing Mutex. When full, oldest
// events are dropped and a drop counter is incremented so the uploader can
// annotate batches with "events_lost" for observability.
// ---------------------------------------------------------------------------

use std::collections::VecDeque;

use crate::edr::EdrEvent;

#[derive(Debug)]
pub struct EventBuffer {
    inner: VecDeque<EdrEvent>,
    capacity: usize,
    dropped: u64,
}

impl EventBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }

    /// Push a new event. Drops the oldest when full.
    pub fn push(&mut self, event: EdrEvent) {
        if self.inner.len() >= self.capacity {
            self.inner.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.inner.push_back(event);
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Drain up to `max` events out of the buffer. Returns an empty vec when
    /// the buffer is empty.
    pub fn drain(&mut self, max: usize) -> Vec<EdrEvent> {
        let take = max.min(self.inner.len());
        self.inner.drain(..take).collect()
    }
}
