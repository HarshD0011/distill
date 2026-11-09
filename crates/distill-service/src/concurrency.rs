//! Shared ceiling for provider requests, including synchronous RPC callers.
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) const MAX_MODEL_REQUESTS: usize = 5;

#[derive(Default)]
pub(super) struct Requests(AtomicUsize);

impl Requests {
    pub(super) fn acquire(&self) -> Result<Permit<'_>, String> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |running| {
                (running < MAX_MODEL_REQUESTS).then_some(running + 1)
            })
            .map(|_| Permit(self))
            .map_err(|_| {
                "All five model request slots are in use; static review requirements retained"
                    .into()
            })
    }

    pub(super) fn in_flight(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

pub(super) struct Permit<'a>(&'a Requests);
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::AcqRel);
    }
}
