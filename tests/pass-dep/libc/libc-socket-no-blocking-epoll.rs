//@ignore-target: windows
//@compile-flags: -Zmiri-disable-isolation

#![feature(io_error_inprogress)]

#[path = "../../utils/libc.rs"]
mod libc_utils;

use std::io::ErrorKind;
use std::thread;
use std::time::Duration;

use libc_utils::epoll::*;
use libc_utils::*;

fn main() {
    test_connect_nonblock();
}

/// Test that connecting to a server socket works when the client
/// socket is non-blocking before the `connect` call.
/// Instead of busy waiting until we no longer get ENOTCONN, we register
/// the client socket to epoll and wait for a WRITABLE event.
fn test_connect_nonblock() {
    let (server_sockfd, addr) = net::make_listener_ipv4().unwrap();
    let client_sockfd =
        unsafe { errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)).unwrap() };
    let epfd = errno_result(unsafe { libc::epoll_create1(0) }).unwrap();

    unsafe {
        // Change client socket to be non-blocking.
        errno_check(libc::fcntl(client_sockfd, libc::F_SETFL, libc::O_NONBLOCK));
    }

    // Spawn the server thread.
    let server_thread = thread::spawn(move || {
        net::accept_ipv4(server_sockfd).unwrap();
    });

    // Yield to server thread to ensure that it's currently accepting.
    thread::sleep(Duration::from_millis(10));

    // Non-blocking connects always "fail" with EINPROGRESS.
    let err = net::connect_ipv4(client_sockfd, addr).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InProgress);

    // Add client socket with WRITABLE interest to epoll.
    epoll_ctl_add(epfd, client_sockfd, EPOLLOUT | EPOLLET | libc::EPOLLERR).unwrap();

    check_epoll_wait::<8>(epfd, &[Ev { events: EPOLLOUT, data: client_sockfd }], -1);

    // TODO: Check SO_ERROR here.

    // We should now be connected and thus getting the peer name should work.
    net::sockname_ipv4(|storage, len| unsafe { libc::getpeername(client_sockfd, storage, len) })
        .unwrap();

    server_thread.join().unwrap();
}
