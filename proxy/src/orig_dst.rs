use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;

use tokio::net::TcpStream;

const SO_ORIGINAL_DST: libc::c_int = 80;

pub fn original_dst(stream: &TcpStream) -> Option<SocketAddr> {
    let fd = stream.as_raw_fd();
    unsafe {
        let mut addr = MaybeUninit::<libc::sockaddr_in>::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            addr.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return None;
        }
        let addr = addr.assume_init();
        if addr.sin_family as i32 != libc::AF_INET {
            return None;
        }
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        if port == 0 {
            return None;
        }
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}
