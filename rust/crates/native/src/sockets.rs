//! Experimental UDP bind helper for the launched native app (port of
//! `scripts/sockets.py`).
//!
//! Authenticate the system app process and act on its transferred socket; do
//! not create a replacement descriptor. Loopback controls and local AWDL
//! binds are separate policies.
use std::collections::BTreeSet;
use std::io;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

use mirra_core::processes::proc_pidpath;
use mirra_core::{sys, Error};

const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERPID: libc::c_int = 2;
const IPV6_BOUND_IF: libc::c_int = 125;
const REQUEST: usize = 36;

/// Link-local IPv6 addresses of `awdl0`.
pub fn local_awdl_addresses() -> io::Result<BTreeSet<Ipv6Addr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(error.kind(), format!("[Errno {}] Cannot enumerate AWDL addresses", error.raw_os_error().unwrap_or(0))));
    }
    let mut addresses = BTreeSet::new();
    let mut item = head;
    while !item.is_null() {
        let value = unsafe { &*item };
        let name = unsafe { std::ffi::CStr::from_ptr(value.ifa_name) }.to_bytes();
        if name == b"awdl0" && !value.ifa_addr.is_null() {
            let address = unsafe { &*value.ifa_addr };
            if address.sa_family as i32 == libc::AF_INET6 && address.sa_len == 28 {
                let raw = unsafe { std::slice::from_raw_parts(value.ifa_addr.cast::<u8>(), 28) };
                let octets: [u8; 16] = raw[8..24].try_into().unwrap();
                let ip = Ipv6Addr::from(octets);
                if ip.segments()[0] & 0xffc0 == 0xfe80 {
                    addresses.insert(ip);
                }
            }
        }
        item = value.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    Ok(addresses)
}

/// Failure classes of `handle`, mirroring Python's exception handlers.
enum Failure {
    /// `PermissionError` → EACCES
    Permission(String),
    /// `OSError` → errno (or EIO)
    Os(i32, String),
    /// `ValueError` → EINVAL
    Value(String),
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        let text = Error::Os(io::Error::from_raw_os_error(error.raw_os_error().unwrap_or(libc::EIO))).to_string();
        match error.raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => Failure::Permission(text),
            Some(libc::EAGAIN) => Failure::Os(libc::EIO, "timed out".into()),
            Some(n) => Failure::Os(n, text),
            None => Failure::Os(libc::EIO, error.to_string()),
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        match error.errno() {
            Some(libc::EACCES) | Some(libc::EPERM) => Failure::Permission(error.to_string()),
            Some(n) => Failure::Os(n, error.to_string()),
            None => Failure::Os(libc::EIO, error.to_string()),
        }
    }
}

fn permission(message: &str) -> Failure {
    Failure::Permission(message.into())
}

fn value(message: &str) -> Failure {
    Failure::Value(message.into())
}

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
}

fn getsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    check(unsafe { libc::getsockopt(fd, level, name, (&mut value as *mut libc::c_int).cast(), &mut length) })?;
    Ok(value)
}

pub struct BindHelper {
    /// Resolved path of the system app executable a peer must run.
    pub expected_executable: String,
    pub bound_count: u64,
    pub allow_awdl: bool,
    pub expected_pid: Option<i32>,
    pub last_failure: Option<String>,
}

impl BindHelper {
    pub fn new(expected_executable: &Path, allow_awdl: bool, expected_pid: Option<i32>) -> Self {
        BindHelper {
            expected_executable: mirra_core::paths::resolve(expected_executable).to_string_lossy().into_owned(),
            bound_count: 0,
            allow_awdl,
            expected_pid,
            last_failure: None,
        }
    }

    /// Peer must be this user, the expected PID (when set), and run the
    /// expected executable.
    fn authorize(&self, fd: RawFd) -> Result<(), Failure> {
        let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 || uid != sys::getuid() {
            return Err(permission("Helper peer has the wrong user"));
        }
        let pid = getsockopt_int(fd, SOL_LOCAL, LOCAL_PEERPID)?;
        if self.expected_pid.is_some_and(|expected| expected != pid) {
            return Err(permission("Helper peer is not the launched app process"));
        }
        let path = proc_pidpath(pid).ok().flatten();
        if path.as_deref() != Some(self.expected_executable.as_bytes()) {
            return Err(permission("Helper peer is not the expected system app"));
        }
        Ok(())
    }

    /// Serve one request on `connection`; replies with a big-endian errno
    /// (0 on success) and returns it. Only a failed reply is an error.
    pub fn handle(&mut self, connection: &std::os::unix::net::UnixStream) -> io::Result<i32> {
        let mut descriptors: Vec<RawFd> = Vec::new();
        connection.set_read_timeout(Some(Duration::from_secs(3)))?;
        connection.set_write_timeout(Some(Duration::from_secs(3)))?;
        let result = self.serve(connection.as_raw_fd(), &mut descriptors);
        for fd in descriptors {
            unsafe { libc::close(fd) };
        }
        let error = match result {
            Ok(()) => {
                self.bound_count += 1;
                0
            }
            Err(Failure::Permission(text)) => {
                self.last_failure = Some(text);
                libc::EACCES
            }
            Err(Failure::Os(errno, text)) => {
                self.last_failure = Some(text);
                errno
            }
            Err(Failure::Value(text)) => {
                self.last_failure = Some(text);
                libc::EINVAL
            }
        };
        use std::io::Write;
        let mut stream = connection;
        stream.write_all(&(error as u32).to_be_bytes())?;
        Ok(error)
    }

    fn serve(&self, fd: RawFd, descriptors: &mut Vec<RawFd>) -> Result<(), Failure> {
        self.authorize(fd)?;
        let mut body = vec![0u8; REQUEST];
        let space = unsafe { libc::CMSG_SPACE((8 * std::mem::size_of::<libc::c_int>()) as u32) } as usize;
        let mut control = vec![0u8; space];
        let mut iov = libc::iovec { iov_base: body.as_mut_ptr().cast(), iov_len: REQUEST };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space as libc::socklen_t;
        let received = loop {
            let n = unsafe { libc::recvmsg(fd, &mut message, 0) };
            if n >= 0 {
                break n as usize;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error.into());
            }
        };
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(header);
                    let length = ((*header).cmsg_len as usize).saturating_sub(data as usize - header as usize);
                    for i in 0..length / std::mem::size_of::<libc::c_int>() {
                        let received_fd = std::ptr::read_unaligned(data.cast::<libc::c_int>().add(i));
                        if received_fd >= 0 {
                            let _ = libc::fcntl(received_fd, libc::F_SETFD, libc::FD_CLOEXEC);
                        }
                        descriptors.push(received_fd);
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        body.truncate(received);
        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || descriptors.len() != 1 {
            return Err(value("Expected exactly one socket descriptor"));
        }
        while body.len() < REQUEST {
            let mut piece = vec![0u8; REQUEST - body.len()];
            let n = loop {
                let n = unsafe { libc::recv(fd, piece.as_mut_ptr().cast(), piece.len(), 0) };
                if n >= 0 {
                    break n as usize;
                }
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINTR) {
                    return Err(error.into());
                }
            };
            if n == 0 {
                return Err(value("Incomplete request"));
            }
            body.extend_from_slice(&piece[..n]);
        }
        if &body[..4] != b"BND1" || u32::from_be_bytes(body[4..8].try_into().unwrap()) != 28 {
            return Err(value("Invalid bind protocol"));
        }
        let addr = &body[8..];
        if addr[0] != 28 || addr[1] as i32 != libc::AF_INET6 {
            return Err(value("Expected a Darwin IPv6 address"));
        }
        let port = u16::from_be_bytes([addr[2], addr[3]]);
        let mut address = Ipv6Addr::from(<[u8; 16]>::try_from(&addr[8..24]).unwrap());
        let mut scope = u32::from_ne_bytes(addr[24..28].try_into().unwrap());
        let udp = unsafe { OwnedFd::from_raw_fd(descriptors.pop().unwrap()) };
        let raw = udp.as_raw_fd();
        // socket(fileno=fd): the descriptor must be a socket.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        check(unsafe { libc::getsockname(raw, (&mut storage as *mut libc::sockaddr_storage).cast(), &mut length) })?;
        if storage.ss_family as i32 != libc::AF_INET6 || getsockopt_int(raw, libc::SOL_SOCKET, libc::SO_TYPE)? != libc::SOCK_DGRAM {
            return Err(value("Expected an IPv6 UDP socket"));
        }
        let bound = unsafe { &*(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
        if bound.sin6_port != 0 {
            return Err(value("Socket is already bound"));
        }
        if port != 0 && port < 1024 {
            return Err(permission("Privileged ports are outside this helper policy"));
        }
        if address != Ipv6Addr::LOCALHOST || scope != 0 {
            if !self.allow_awdl {
                return Err(permission("This probe permits loopback only"));
            }
            let interface = unsafe { libc::if_nametoindex(c"awdl0".as_ptr()) };
            if interface == 0 {
                return Err(Failure::Os(libc::EIO, "no interface with this name".into()));
            }
            let local = local_awdl_addresses()?;
            let bound_interface = getsockopt_int(raw, libc::IPPROTO_IPV6, IPV6_BOUND_IF)? as u32;
            if address == Ipv6Addr::UNSPECIFIED && scope == 0 && bound_interface == interface {
                // Constrain an interface-bound wildcard reservation to this
                // host's actual AWDL address, retaining its port.
                let mut texts: Vec<(String, Ipv6Addr)> = local.iter().map(|a| (a.to_string(), *a)).collect();
                texts.sort();
                let Some((_, first)) = texts.first() else { return Err(permission("No local AWDL address")) };
                address = *first;
                scope = interface;
            }
            if !local.contains(&address) || (scope != 0 && scope != interface)
                || (bound_interface != 0 && bound_interface != interface) {
                return Err(permission("Socket is not a local AWDL reservation"));
            }
            scope = interface;
        }
        let mut target: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        target.sin6_len = 28;
        target.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        target.sin6_port = port.to_be();
        target.sin6_flowinfo = 0;
        target.sin6_addr = libc::in6_addr { s6_addr: address.octets() };
        target.sin6_scope_id = scope;
        check(unsafe { libc::bind(raw, (&target as *const libc::sockaddr_in6).cast(), 28) })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    fn own_executable() -> std::path::PathBuf {
        std::path::PathBuf::from(String::from_utf8(proc_pidpath(std::process::id() as i32).unwrap().unwrap()).unwrap())
    }

    fn socket(kind: libc::c_int) -> OwnedFd {
        let fd = unsafe { libc::socket(libc::AF_INET6, kind, 0) };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn request(address: Ipv6Addr, port: u16, scope: u32) -> Vec<u8> {
        let mut body = b"BND1".to_vec();
        body.extend_from_slice(&28u32.to_be_bytes());
        body.extend_from_slice(&[28, libc::AF_INET6 as u8]);
        body.extend_from_slice(&port.to_be_bytes());
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&address.octets());
        body.extend_from_slice(&scope.to_ne_bytes());
        body
    }

    fn send(stream: &UnixStream, body: &[u8], fds: &[RawFd]) {
        let space = unsafe { libc::CMSG_SPACE((fds.len().max(1) * 4) as u32) } as usize;
        let mut control = vec![0u8; space];
        let mut iov = libc::iovec { iov_base: body.as_ptr() as *mut _, iov_len: body.len() };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if !fds.is_empty() {
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = space as libc::socklen_t;
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN((fds.len() * 4) as u32) as _;
                for (i, fd) in fds.iter().enumerate() {
                    std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>().add(i), *fd);
                }
            }
        }
        assert_eq!(unsafe { libc::sendmsg(stream.as_raw_fd(), &message, 0) }, body.len() as isize);
    }

    fn exchange(helper: &mut BindHelper, body: &[u8], fds: &[RawFd]) -> i32 {
        let (mut client, server) = UnixStream::pair().unwrap();
        send(&client, body, fds);
        let result = helper.handle(&server).unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(u32::from_be_bytes(reply) as i32, result);
        result
    }

    fn bound_port(fd: &OwnedFd) -> u16 {
        let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut length = 28 as libc::socklen_t;
        unsafe { libc::getsockname(fd.as_raw_fd(), (&mut address as *mut libc::sockaddr_in6).cast(), &mut length) };
        u16::from_be(address.sin6_port)
    }

    #[test]
    fn loopback_socket_is_bound_in_place() {
        let mut helper = BindHelper::new(&own_executable(), false, Some(std::process::id() as i32));
        let udp = socket(libc::SOCK_DGRAM);
        assert_eq!(exchange(&mut helper, &request(Ipv6Addr::LOCALHOST, 0, 0), &[udp.as_raw_fd()]), 0);
        assert_eq!(helper.bound_count, 1);
        assert_ne!(bound_port(&udp), 0);
        // The same descriptor cannot be bound twice.
        assert_eq!(exchange(&mut helper, &request(Ipv6Addr::LOCALHOST, 0, 0), &[udp.as_raw_fd()]), libc::EINVAL);
        assert_eq!(helper.last_failure.as_deref(), Some("Socket is already bound"));
    }

    #[test]
    fn peer_identity_is_required() {
        let udp = socket(libc::SOCK_DGRAM);
        let mut helper = BindHelper::new(Path::new("/System/Applications/iPhone Mirroring.app/Contents/MacOS/iPhone Mirroring"), true, None);
        assert_eq!(exchange(&mut helper, &request(Ipv6Addr::LOCALHOST, 0, 0), &[udp.as_raw_fd()]), libc::EACCES);
        assert_eq!(helper.last_failure.as_deref(), Some("Helper peer is not the expected system app"));
        let mut helper = BindHelper::new(&own_executable(), false, Some(1));
        assert_eq!(exchange(&mut helper, &request(Ipv6Addr::LOCALHOST, 0, 0), &[udp.as_raw_fd()]), libc::EACCES);
        assert_eq!(helper.last_failure.as_deref(), Some("Helper peer is not the launched app process"));
        assert_eq!(helper.bound_count, 0);
        assert_eq!(bound_port(&udp), 0);
    }

    #[test]
    fn policy_and_protocol_failures_are_reported() {
        let mut helper = BindHelper::new(&own_executable(), false, None);
        let udp = socket(libc::SOCK_DGRAM);
        let fd = udp.as_raw_fd();
        let cases: Vec<(Vec<u8>, Vec<RawFd>, i32, &str)> = vec![
            (request(Ipv6Addr::LOCALHOST, 80, 0), vec![fd], libc::EACCES, "Privileged ports are outside this helper policy"),
            (request(Ipv6Addr::UNSPECIFIED, 0, 0), vec![fd], libc::EACCES, "This probe permits loopback only"),
            (request(Ipv6Addr::LOCALHOST, 0, 0), vec![], libc::EINVAL, "Expected exactly one socket descriptor"),
            (request(Ipv6Addr::LOCALHOST, 0, 0), vec![fd, fd], libc::EINVAL, "Expected exactly one socket descriptor"),
            (b"BND2".iter().copied().chain(request(Ipv6Addr::LOCALHOST, 0, 0)[4..].iter().copied()).collect(), vec![fd],
                libc::EINVAL, "Invalid bind protocol"),
        ];
        for (body, fds, expected, failure) in cases {
            assert_eq!(exchange(&mut helper, &body, &fds), expected, "{}", failure);
            assert_eq!(helper.last_failure.as_deref(), Some(failure));
        }
        let tcp = socket(libc::SOCK_STREAM);
        assert_eq!(exchange(&mut helper, &request(Ipv6Addr::LOCALHOST, 0, 0), &[tcp.as_raw_fd()]), libc::EINVAL);
        assert_eq!(helper.last_failure.as_deref(), Some("Expected an IPv6 UDP socket"));
        // A truncated request is incomplete once the peer closes.
        let (client, server) = UnixStream::pair().unwrap();
        send(&client, &request(Ipv6Addr::LOCALHOST, 0, 0)[..20], &[fd]);
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(helper.handle(&server).unwrap(), libc::EINVAL);
        assert_eq!(helper.last_failure.as_deref(), Some("Incomplete request"));
        assert_eq!(helper.bound_count, 0);
    }
}
