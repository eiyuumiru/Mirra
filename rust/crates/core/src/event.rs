//! `threading.Event` equivalent.
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
pub struct Event {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

impl Event {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self) {
        let (lock, condition) = &*self.inner;
        *lock.lock().unwrap() = true;
        condition.notify_all();
    }

    pub fn clear(&self) {
        *self.inner.0.lock().unwrap() = false;
    }

    pub fn is_set(&self) -> bool {
        *self.inner.0.lock().unwrap()
    }

    /// Wait up to `timeout` (forever when `None`); returns the flag.
    pub fn wait(&self, timeout: Option<Duration>) -> bool {
        let (lock, condition) = &*self.inner;
        let mut flag = lock.lock().unwrap();
        match timeout {
            None => {
                while !*flag {
                    flag = condition.wait(flag).unwrap();
                }
                true
            }
            Some(timeout) => {
                let deadline = Instant::now() + timeout;
                while !*flag {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    flag = condition.wait_timeout(flag, deadline - now).unwrap().0;
                }
                *flag
            }
        }
    }
}
