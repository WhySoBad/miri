//@only-target: linux android freebsd solaris illumos # Currently we only support targets which can create non-blocking sockets using the `socket` syscall.
//@compile-flags: -Zmiri-disable-isolation
//@revisions: windows_host apple_host other_unix_host
//@[other_unix_host] ignore-host: windows apple
//@[windows_host] only-host: windows
//@[apple_host] only-host: apple

#![feature(io_error_inprogress)]

#[path = "../../utils/libc.rs"]
mod libc_utils;

use std::io::ErrorKind;
use std::thread;
use std::time::Duration;

use libc_utils::*;

const TEST_BYTES: &[u8] = b"these are some test bytes!";

fn main() {
    test_accept_nonblock();
    test_send_recv_nonblock();
    test_write_read_nonblock();

    test_getpeername_ipv4_nonblock();
}

/// Test that nonblocking TCP server sockets return [`io::ErrorKind::WouldBlock`] when trying
/// to accept when no incoming connection exists. This also tests that nonblocking server sockets
/// are still able to accept incoming connections should they already exist before the `accept` or
/// `accept4` syscall is called.
fn test_accept_nonblock() {
    // Create a new non-blocking server socket.
    let (server_sockfd, addr) = net::make_listener_ipv4(libc::SOCK_NONBLOCK).unwrap();
    let client_sockfd =
        unsafe { errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)).unwrap() };

    // This should fail as we don't have an incoming connection for this address.
    let err = net::accept_ipv4(server_sockfd).unwrap_err();
    // Assert that either EAGAIN or EWOULDBLOCK was returned.
    assert_eq!(err.kind(), ErrorKind::WouldBlock);

    let t1 = thread::spawn(move || {
        // Instantly yield to main thread to ensure that the `connect` syscall
        // was called before we call the `accept` on the server.
        thread::sleep(Duration::from_millis(10));

        net::accept_ipv4(server_sockfd).unwrap();
    });

    net::connect_ipv4(client_sockfd, addr);

    t1.join().unwrap();
}

/// Test sending bytes into and receiving bytes from a connected stream without blocking.
fn test_send_recv_nonblock() {
    let (server_sockfd, addr) = net::make_listener_ipv4(0).unwrap();
    // Create a new non-blocking client socket.
    let client_sockfd = unsafe {
        errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0))
            .unwrap()
    };

    // Spawn the server thread.
    let server_thread = thread::spawn(move || {
        let (peerfd, _) = net::accept_ipv4(server_sockfd).unwrap();

        // Yield back to client to test that attempting to receive from a socket
        // which has an empty buffer would block.
        thread::sleep(Duration::from_millis(10));

        let bytes_written = unsafe {
            errno_result(libc_utils::net::send_all(
                peerfd,
                TEST_BYTES.as_ptr().cast(),
                TEST_BYTES.len(),
                0,
            ))
            .unwrap()
        };
        assert_eq!(bytes_written as usize, TEST_BYTES.len());

        // Yield back to the client thread which now attempts to read
        // and then to fill the receive buffer of the peerfd socket.
        thread::sleep(Duration::from_millis(10));

        // The buffer should contain `TEST_BYTES` at the beginning.
        let mut buffer = [0; TEST_BYTES.len()];
        let bytes_read = unsafe {
            errno_result(libc_utils::net::recv_all(
                peerfd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            ))
            .unwrap()
        };

        assert_eq!(bytes_read as usize, TEST_BYTES.len());
        assert_eq!(&buffer, TEST_BYTES);

        if cfg!(any(other_unix_host, apple_host)) {
            // We can only test whether non-blocking writes would block once the buffer is full
            // on UNIX hosts.

            // After the `TEST_BYTES` the buffer should only contain ones.
            // We exemplary test that some bytes were written, but since we don't know the
            // exact buffer size (or how many bytes were exactly written before the EWOULDBLOCK)
            // we can't read the whole buffer.
            let mut buffer = [0; 1000];
            let bytes_read = unsafe {
                errno_result(libc_utils::net::recv_all(
                    peerfd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                ))
                .unwrap()
            };

            assert_eq!(bytes_read as usize, buffer.len());
            assert_eq!(&buffer, &[1u8; 1000]);
        }
    });

    // Yield to server thread to ensure that it's currently accepting.
    thread::sleep(Duration::from_millis(10));

    // Non-blocking connects always "fail" with EINPROGRESS.
    let err = unsafe {
        errno_result(libc::connect(
            client_sockfd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ))
        .unwrap_err()
    };
    assert_eq!(err.kind(), ErrorKind::InProgress);

    // We are connecting and the server socket is not writing.

    let mut buffer = [0; TEST_BYTES.len()];
    // Receiving from a socket when the peer is not writing is
    // not possible without blocking.
    let err = unsafe {
        errno_result(libc_utils::net::recv_all(
            client_sockfd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
        ))
        .unwrap_err()
    };
    assert_eq!(err.kind(), ErrorKind::WouldBlock);

    // Yield to server thread to send some bytes into the peer socket.
    thread::sleep(Duration::from_millis(250));

    // Receiving bytes from the peer socket without blocking should now
    // succeed as the peer socket is writing.
    let bytes_read = unsafe {
        errno_result(libc_utils::net::recv_all(
            client_sockfd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
        ))
        .unwrap()
    };

    assert_eq!(bytes_read as usize, TEST_BYTES.len());
    assert_eq!(&buffer, TEST_BYTES);

    // Now we test non-blocking writing.

    // Sending into the empty buffer should succeed without blocking.
    let bytes_written = unsafe {
        errno_result(libc_utils::net::send_all(
            client_sockfd,
            TEST_BYTES.as_ptr().cast(),
            TEST_BYTES.len(),
            0,
        ))
        .unwrap()
    };
    assert_eq!(bytes_written as usize, TEST_BYTES.len());

    if cfg!(any(apple_host, other_unix_host)) {
        // We can only test filling the buffer on UNIX because on
        // Windows the receive buffer of a localhost socket dynamically
        // grows.

        let fill_buf = [1u8; 5_000_000];
        // This fills the socket receive buffer and thus should start blocking.
        let err = unsafe {
            errno_result(libc_utils::net::send_all(
                client_sockfd,
                fill_buf.as_ptr().cast(),
                fill_buf.len(),
                0,
            ))
            .unwrap_err()
        };
        assert_eq!(err.kind(), ErrorKind::WouldBlock)
    }

    server_thread.join().unwrap();
}

/// Test writing bytes into and reading bytes from a connected stream without blocking.
fn test_write_read_nonblock() {
    let (server_sockfd, addr) = net::make_listener_ipv4(0).unwrap();
    // Create a new non-blocking client socket.
    let client_sockfd = unsafe {
        errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0))
            .unwrap()
    };

    // Spawn the server thread.
    let server_thread = thread::spawn(move || {
        let (peerfd, _) = net::accept_ipv4(server_sockfd).unwrap();

        // Yield back to client to test that attempting to read from a socket
        // which has an empty buffer would block.
        thread::sleep(Duration::from_millis(10));

        let bytes_written = unsafe {
            errno_result(libc_utils::write_all(
                peerfd,
                TEST_BYTES.as_ptr().cast(),
                TEST_BYTES.len(),
            ))
            .unwrap()
        };
        assert_eq!(bytes_written as usize, TEST_BYTES.len());

        // Yield back to the client thread which now attempts to read
        // and then to fill the receive buffer of the peerfd socket.
        thread::sleep(Duration::from_millis(10));

        // The buffer should contain `TEST_BYTES` at the beginning.
        let mut buffer = [0; TEST_BYTES.len()];
        let bytes_read = unsafe {
            errno_result(libc_utils::read_all(peerfd, buffer.as_mut_ptr().cast(), buffer.len()))
                .unwrap()
        };

        assert_eq!(bytes_read as usize, TEST_BYTES.len());
        assert_eq!(&buffer, TEST_BYTES);

        if cfg!(any(other_unix_host, apple_host)) {
            // We can only test whether non-blocking writes would block once the buffer is full
            // on UNIX hosts.

            // After the `TEST_BYTES` the buffer should only contain ones.
            // We exemplary test that some bytes were written, but since we don't know the
            // exact buffer size (or how many bytes were exactly written before the EWOULDBLOCK)
            // we can't read the whole buffer.
            let mut buffer = [0; 1000];
            let bytes_read = unsafe {
                errno_result(libc_utils::read_all(peerfd, buffer.as_mut_ptr().cast(), buffer.len()))
                    .unwrap()
            };

            assert_eq!(bytes_read as usize, buffer.len());
            assert_eq!(&buffer, &[1u8; 1000]);
        }
    });

    // Yield to server thread to ensure that it's currently accepting.
    thread::sleep(Duration::from_millis(10));

    // Non-blocking connects always "fail" with EINPROGRESS.
    let err = unsafe {
        errno_result(libc::connect(
            client_sockfd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ))
        .unwrap_err()
    };
    assert_eq!(err.kind(), ErrorKind::InProgress);

    // We are connecting and the server socket is not writing.

    let mut buffer = [0; TEST_BYTES.len()];
    // Reading from a socket when the peer is not writing is
    // not possible without blocking.
    let err = unsafe {
        errno_result(libc_utils::read_all(
            client_sockfd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
        ))
        .unwrap_err()
    };
    assert_eq!(err.kind(), ErrorKind::WouldBlock);

    // Yield to server thread to write some bytes into the peer socket.
    thread::sleep(Duration::from_millis(250));

    // Reading bytes from the peer socket without blocking should now
    // succeed as the peer socket is writing.
    let bytes_read = unsafe {
        errno_result(libc_utils::read_all(client_sockfd, buffer.as_mut_ptr().cast(), buffer.len()))
            .unwrap()
    };

    assert_eq!(bytes_read as usize, TEST_BYTES.len());
    assert_eq!(&buffer, TEST_BYTES);

    // Now we test non-blocking writing.

    // Writing into the empty buffer should succeed without blocking.
    let bytes_written = unsafe {
        errno_result(libc_utils::write_all(
            client_sockfd,
            TEST_BYTES.as_ptr().cast(),
            TEST_BYTES.len(),
        ))
        .unwrap()
    };
    assert_eq!(bytes_written as usize, TEST_BYTES.len());

    if cfg!(any(other_unix_host, apple_host)) {
        // We can only test filling the buffer on UNIX because on
        // Windows the receive buffer of a localhost socket dynamically
        // grows.

        let fill_buf = [1u8; 5_000_000];
        // This fills the socket receive buffer and thus should start blocking.
        let err = unsafe {
            errno_result(libc_utils::write_all(
                client_sockfd,
                fill_buf.as_ptr().cast(),
                fill_buf.len(),
            ))
            .unwrap_err()
        };
        assert_eq!(err.kind(), ErrorKind::WouldBlock)
    }

    server_thread.join().unwrap();
}

/// Test the `getpeername` syscall on a non-blocking IPv4 socket.
/// For a connecting socket, the `getpeername` syscall should
/// return an EINPROGRESS whilst for connected sockets it should
/// return the same address as the socket was connected to.
fn test_getpeername_ipv4_nonblock() {
    // Create a new non-blocking client socket.
    let client_sockfd = unsafe {
        errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0))
            .unwrap()
    };

    // Blackhole address where the socket stays in connecting state but never
    // successfully connects.
    let blackhole_addr = net::sock_addr_ipv4([192, 0, 2, 1], 0);

    let err = unsafe {
        errno_result(libc::connect(
            client_sockfd,
            (&blackhole_addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ))
        .unwrap_err()
    };

    // Non-blocking connect should fail with EINPROGRESS.
    match err.kind() {
        ErrorKind::InProgress => { /* fall-through to below */ }
        ErrorKind::AddrNotAvailable => {
            // Windows and Apple hosts won't attempt
            // to connect to the blackhole IP address
            // and just return EADDRNOTAVAIL.
            // In those cases we need to abort the
            // test since the subsequent statements
            // rely on the assumption that the socket is
            // still not successfully connected.
            assert!(
                cfg!(any(windows_host, apple_host)),
                "only Windows and Apple hosts ignore blackhole IP addresses"
            );
            return;
        }
        // All other errors should not happen.
        _ => panic!(),
    }

    assert!(cfg!(other_unix_host), "blackhole IP addresses only work on non-apple UNIX hosts");

    // Since we're connecting to a blackhole IP address, the socket should never be
    // successfully connected and thus we should be unable to read the peername.
    let Err(err) = net::sockname_ipv4(|storage, len| unsafe {
        libc::getpeername(client_sockfd, storage, len)
    }) else {
        unreachable!()
    };
    assert_eq!(err.kind(), ErrorKind::NotConnected);

    let (server_sockfd, addr) = net::make_listener_ipv4(0).unwrap();
    // Create a new non-blocking client socket.
    let client_sockfd = unsafe {
        errno_result(libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0))
            .unwrap()
    };

    // Spawn the server thread.
    let server_thread = thread::spawn(move || {
        net::accept_ipv4(server_sockfd).unwrap();
    });

    // Yield to server thread to ensure that it's currently accepting.
    thread::sleep(Duration::from_millis(10));

    // Non-blocking connects always "fail" with EINPROGRESS.
    let err = unsafe {
        errno_result(libc::connect(
            client_sockfd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ))
        .unwrap_err()
    };
    assert_eq!(err.kind(), ErrorKind::InProgress);

    // It should be reasonable to assume that a localhost connection should be established
    // within 20ms.
    thread::sleep(Duration::from_millis(20));

    let (_, peer_addr) = net::sockname_ipv4(|storage, len| unsafe {
        libc::getpeername(client_sockfd, storage, len)
    })
    .unwrap();

    assert_eq!(addr.sin_family, peer_addr.sin_family);
    assert_eq!(addr.sin_port, peer_addr.sin_port);
    assert_eq!(addr.sin_addr.s_addr, peer_addr.sin_addr.s_addr);

    server_thread.join().unwrap();
}
