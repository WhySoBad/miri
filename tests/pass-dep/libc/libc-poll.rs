//@ignore-target: windows # no libc

use std::time::{Duration, Instant};

#[path = "../../utils/libc.rs"]
mod libc_utils;
use libc_utils::*;

// The tests for `poll` are pretty sparse because `poll` is internally implemented using
// level-triggered epoll. We thus only need to test the `poll` specific functionality here.

fn main() {
    test_poll_unblock_with_events();
    test_poll_block_without_events();
    test_poll_duplicate_fd_interest();
}

/// Test that the `poll` call unblocks when one of the
/// provided interests is fulfilled.
fn test_poll_unblock_with_events() {
    let flags = libc::EFD_NONBLOCK | libc::EFD_CLOEXEC;
    let fd = errno_result(unsafe { libc::eventfd(0, flags) }).unwrap();

    let mut interests = [libc::pollfd { fd, events: libc::POLLIN | libc::POLLOUT, revents: 0 }];
    let ready = unsafe {
        errno_result(libc::poll(interests.as_mut_ptr(), interests.len() as libc::nfds_t, -1))
            .unwrap()
    };
    assert_eq!(ready, 1);
    // Ensure that the correct `revents` has been set.
    assert_eq!(interests[0].revents, libc::POLLOUT);
}

/// Test that the `poll` blocks and returns zero when
/// none of the provided interests get fulfilled.
fn test_poll_block_without_events() {
    let flags = libc::EFD_NONBLOCK | libc::EFD_CLOEXEC;
    let fd = errno_result(unsafe { libc::eventfd(0, flags) }).unwrap();

    let mut interests = [libc::pollfd { fd, events: libc::POLLIN, revents: 0 }];
    let before = Instant::now();
    let ready = unsafe {
        errno_result(libc::poll(interests.as_mut_ptr(), interests.len() as libc::nfds_t, 50))
            .unwrap()
    };
    assert_eq!(ready, 0);
    // Ensure that the `poll` blocked at least for 50ms.
    assert!(Instant::now().duration_since(before) > Duration::from_millis(50))
}

/// Test calling `poll` when the same fd is present multiple times in the
/// interest array. This should set the `revents` for both entries in the
/// interest array.
fn test_poll_duplicate_fd_interest() {
    let flags = libc::EFD_NONBLOCK | libc::EFD_CLOEXEC;
    let fd = errno_result(unsafe { libc::eventfd(0, flags) }).unwrap();

    let mut interests = [
        libc::pollfd { fd, events: libc::POLLIN | libc::POLLOUT, revents: 0 },
        libc::pollfd { fd, events: libc::POLLIN | libc::POLLOUT, revents: 0 },
    ];
    let ready = unsafe {
        errno_result(libc::poll(interests.as_mut_ptr(), interests.len() as libc::nfds_t, -1))
            .unwrap()
    };
    assert_eq!(ready, 2);
    // Ensure that both `revents` have been set.
    assert_eq!(interests[0].revents, libc::POLLOUT);
    assert_eq!(interests[1].revents, libc::POLLOUT);
}
