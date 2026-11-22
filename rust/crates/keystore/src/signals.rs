//! `signal.signal(SIGTERM/SIGINT, handler)` for the long-running commands.
//!
//! The async-signal handler only writes one byte to a pipe; a thread runs
//! the callback, like Python's main-thread signal handlers.
use std::sync::atomic::{AtomicI32, Ordering};

static WRITER: AtomicI32 = AtomicI32::new(-1);

extern "C" fn notify(_signal: libc::c_int) {
    let fd = WRITER.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe {
            let saved = *libc::__error();
            let byte = 1u8;
            libc::write(fd, (&byte as *const u8).cast(), 1);
            *libc::__error() = saved;
        }
    }
}

/// Run `callback` (on a helper thread) whenever SIGTERM or SIGINT arrives.
/// Installs process-wide handlers; call once per process.
pub fn on_termination<F: Fn() + Send + 'static>(callback: F) -> std::io::Result<()> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for fd in fds {
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    unsafe { libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK) };
    let previous = WRITER.swap(fds[1], Ordering::SeqCst);
    let reader = fds[0];
    std::thread::Builder::new().name("termination-signals".into()).spawn(move || {
        let mut buffer = [0u8; 16];
        loop {
            let n = unsafe { libc::read(reader, buffer.as_mut_ptr().cast(), buffer.len()) };
            if n < 0 && mirra_core::sys::errno() == libc::EINTR {
                continue;
            }
            if n <= 0 {
                return;
            }
            callback();
        }
    })?;
    if previous >= 0 {
        unsafe { libc::close(previous) };
    }
    for signal in [libc::SIGTERM, libc::SIGINT] {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = notify as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}
