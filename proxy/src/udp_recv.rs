use std::io::{self, Error, ErrorKind};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdp};
use std::os::fd::AsRawFd;

use tokio::net::UdpSocket;

const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IP_ORIGDSTADDR: libc::c_int = 20;

pub fn bind_udp(addr: &str) -> io::Result<UdpSocket> {
    let std = StdUdp::bind(addr)?;
    std.set_nonblocking(true)?;
    let fd = std.as_raw_fd();
    let yes: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR,
            &yes as *const _ as *const libc::c_void,
            std::mem::size_of_val(&yes) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &yes as *const _ as *const libc::c_void,
            std::mem::size_of_val(&yes) as libc::socklen_t,
        );
    }
    UdpSocket::from_std(std)
}

pub fn recv_from_orig(sock: &UdpSocket) -> io::Result<(Vec<u8>, SocketAddr, Option<SocketAddr>)> {
    let fd = sock.as_raw_fd();
    let mut buf = vec![0u8; 2048];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut cbuf = [0u8; 128];
    let mut src = MaybeUninit::<libc::sockaddr_in>::zeroed();
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = src.as_mut_ptr() as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cbuf.len() as _;
        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(Error::last_os_error());
        }
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "udp eof"));
        }
        buf.truncate(n as usize);
        let src = src.assume_init();
        if src.sin_family as i32 != libc::AF_INET {
            return Err(Error::new(ErrorKind::InvalidData, "not ipv4"));
        }
        let peer = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(src.sin_addr.s_addr)),
            u16::from_be(src.sin_port),
        ));
        let orig = parse_origdst(&msg);
        Ok((buf, peer, orig))
    }
}

unsafe fn parse_origdst(msg: &libc::msghdr) -> Option<SocketAddr> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    while !cmsg.is_null() {
        let hdr = &*cmsg;
        if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == IP_ORIGDSTADDR {
            let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
            let addr = *data;
            if addr.sin_family as i32 == libc::AF_INET {
                let port = u16::from_be(addr.sin_port);
                if port != 0 {
                    return Some(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                        port,
                    )));
                }
            }
        }
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    None
}
