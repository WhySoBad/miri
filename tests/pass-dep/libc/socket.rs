//@ignore-target: windows # No libc socket on Windows
//@ignore-target: solaris # Does socket is a macro for __xnet7_socket which has no shim
//@ignore-target: illumos # Does socket is a macro for __xnet7_socket which has no shim
//@ignore-target: netbsd # socket is a macro fro __socket30 which has no shim
//@compile-flags: -Zmiri-disable-isolation

use std::net::TcpListener;

fn main() {
    create_listener();
}

fn create_listener() {
    let _listener = TcpListener::bind("127.0.0.1:1234").unwrap();
}
