//! SIGTERM/SIGINT handlers (`signal.signal(sig, handler)`): the handler only
//! records the signal; the callback runs on an ordinary thread.
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

use mirra_core::sys;

static PIPE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(_: libc::c_int) {
    let fd = PIPE.load(Ordering::SeqCst);
    if fd >= 0 {
        let byte = 1u8;
        unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    }
}

/// Installed for the rest of the process (entry functions run once per process).
pub struct StopSignals {
    flag: Arc<AtomicBool>,
}

impl StopSignals {
    pub fn install() -> Self {
        Self::install_with(|| {})
    }

    /// Run `callback` (on a helper thread) for every SIGTERM/SIGINT.
    pub fn install_with(callback: impl Fn() + Send + 'static) -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let mut fds = [0; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
            for fd in fds {
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
            let (reader, writer) = (fds[0], fds[1]);
            let seen = flag.clone();
            let _ = std::thread::Builder::new().name("stop-signals".into()).spawn(move || {
                let mut buffer = [0u8; 16];
                loop {
                    let n = unsafe { libc::read(reader, buffer.as_mut_ptr().cast(), buffer.len()) };
                    if n < 0 && sys::errno() == libc::EINTR {
                        continue;
                    }
                    if n <= 0 {
                        return;
                    }
                    seen.store(true, Ordering::SeqCst);
                    callback();
                }
            });
            PIPE.store(writer, Ordering::SeqCst);
            for signal in [libc::SIGINT, libc::SIGTERM] {
                unsafe {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    action.sa_sigaction = on_signal as *const () as usize;
                    action.sa_flags = libc::SA_RESTART;
                    libc::sigemptyset(&mut action.sa_mask);
                    libc::sigaction(signal, &action, std::ptr::null_mut());
                }
            }
        }
        StopSignals { flag }
    }

    pub fn stopped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}
