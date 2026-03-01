//@ignore-target: windows # No libc socket on Windows
//@ignore-target: solaris # socket is a macro for __xnet7_socket which has no shim
//@ignore-target: illumos # socket is a macro for __xnet7_socket which has no shim
//@ignore-target: netbsd # socket is a macro fro __socket30 which has no shim
//@compile-flags: -Zmiri-disable-isolation

#[path = "../../utils/libc.rs"]
mod libc_utils;
use libc_utils::*;

fn main() {
    let sockfd =
        unsafe { errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)).unwrap() };
    let addr = net::ipv4_sock_addr("127.0.0.1:1234").unwrap();
    unsafe {
        errno_check(libc::bind(
            sockfd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ));

        let errno = libc::setsockopt //~ ERROR: option SO_REUSEADDR on level SOL_SOCKET can only be set before calling `bind`
            (sockfd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&1 as *const libc::c_int).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        );

        errno_check(errno);
    }
}
