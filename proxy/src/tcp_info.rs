use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;

use tokio::net::TcpStream;

/// Kernel TCP_INFO: (rtt_us, total_retrans).
pub fn tcp_kernel_info(stream: &TcpStream) -> Option<(u32, u32)> {
    let fd = stream.as_raw_fd();
    unsafe {
        let mut info = MaybeUninit::<libc::tcp_info>::zeroed();
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_INFO,
            info.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return None;
        }
        let info = info.assume_init();
        Some((info.tcpi_rtt, info.tcpi_total_retrans))
    }
}
