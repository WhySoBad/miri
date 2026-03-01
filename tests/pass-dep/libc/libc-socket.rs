//@ignore-target: windows # No libc socket on Windows
//@ignore-target: solaris # Socket is a macro for __xnet7_socket which has no shim
//@ignore-target: illumos # Socket is a macro for __xnet7_socket which has no shim
//@ignore-target: netbsd # Socket is a macro for __socket30 which has no shim
//@compile-flags: -Zmiri-disable-isolation

#[path = "../../utils/libc.rs"]
mod libc_utils;
use std::io::ErrorKind;

use libc_utils::*;

fn main() {
    test_socket_close();
    test_bind_ipv4();
    #[cfg(any(target_os = "macos", target_os = "dragonfly"))]
    test_bind_ipv4_nosigpipe();
    test_bind_ipv4_invalid_addr_len();
    test_bind_ipv6();
    test_listen();
}

fn test_socket_close() {
    unsafe {
        let sockfd = errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)).unwrap();
        errno_check(libc::close(sockfd));
    }
}

fn test_bind_ipv4() {
    let sockfd =
        unsafe { errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)).unwrap() };
    let addr = net::ipv4_sock_addr("0.0.0.0:1234").unwrap();
    unsafe {
        errno_check(libc::bind(
            sockfd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ));
    }
}

#[cfg(any(target_os = "macos", target_os = "dragonfly"))]
fn test_bind_ipv4_nosigpipe() {
    let sockfd =
        unsafe { errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)).unwrap() };
    let addr = net::ipv4_sock_addr("0.0.0.0:1234").unwrap();
    unsafe {
        errno_check(libc::setsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&1 as *const libc::c_int).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        ));
        errno_check(libc::bind(
            sockfd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ));
    }
}

fn test_bind_ipv4_invalid_addr_len() {
    let sockfd =
        unsafe { errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)).unwrap() };
    let addr = net::ipv4_sock_addr("0.0.0.0:1234").unwrap();
    let err = unsafe {
        errno_result(libc::bind(
            sockfd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            (size_of::<libc::sockaddr_in>() + 1) as libc::socklen_t,
        ))
        .unwrap_err()
    };
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    // check that it is the right kind of `InvalidInput`
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

fn test_bind_ipv6() {
    let sockfd =
        unsafe { errno_result(libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0)).unwrap() };
    let addr = net::ipv6_sock_addr("[::]:1234").unwrap();
    unsafe {
        errno_check(libc::bind(
            sockfd,
            (&addr as *const libc::sockaddr_in6).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ));
    }
}

fn test_listen() {
    let sockfd =
        unsafe { errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)).unwrap() };
    let addr = net::ipv4_sock_addr("0.0.0.0:1234").unwrap();
    unsafe {
        errno_check(libc::setsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&1 as *const libc::c_int).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        ));

        errno_check(libc::bind(
            sockfd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ));
    }

    #[cfg(target_os = "horizon")]
    let backlog = 20;
    #[cfg(target_os = "haiku")]
    let backlog = 32;
    #[cfg(all(not(target_os = "haiku"), not(target_os = "horizon")))]
    let backlog = 128;

    unsafe {
        errno_check(libc::listen(sockfd, backlog));
    }
}
