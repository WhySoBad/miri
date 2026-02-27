use std::cell::{Cell, RefCell};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};

use rustc_abi::Size;
use rustc_const_eval::interpret::{InterpResult, interp_ok};
use rustc_middle::throw_unsup_format;
use rustc_target::spec::Os;

use crate::shims::files::{FdId, FileDescription};
use crate::{OpTy, Scalar, *};

#[derive(Debug, PartialEq)]
enum SocketFamily {
    // IPv4 internet protocols
    IPv4,
    // IPv6 internet protocols
    IPv6,
}

#[derive(Debug)]
enum SocketType {
    /// Reliable full-duplex communication, based on connections.
    Stream,
}

#[allow(unused)]
#[derive(Debug)]
enum SocketKind {
    TcpListener(TcpListener),
    TcpStream(TcpStream),
}

#[derive(Debug)]
enum SocketState {
    /// No syscall after `socket` has been made.
    Initial,
    /// The `bind` syscall has been called on the socket.
    /// This is only reachable from the [`SetupState::NoSigpipe`] state.
    Bind(SocketAddr),
    /// The `listen` syscall has been called on the socket.
    /// This is only reachable from the [`SetupState::Bind`] state.
    TcpListener(TcpListener),
}

#[allow(unused)]
#[derive(Debug)]
struct Socket {
    /// Family of the socket, used to ensure socket only binds/connects to address of
    /// same family.
    family: SocketFamily,
    /// Type of the socket, either datagram or stream.
    /// Only stream is supported at the moment!
    socket_type: SocketType,
    /// Current state of the inner socket.
    state: RefCell<SocketState>,
    /// Whether this fd is non-blocking or not.
    is_non_block: Cell<bool>,
    /// Whether the `SO_NOSIGPIPE` socket option has been set.
    /// This option is only allowed on MacOS, FreeBSD, NetBSD, and Dragonfly targets and
    /// can only be set directly after calling `socket` (before any other syscall interacts
    /// with the socket).
    has_no_sig_pipe: Cell<bool>,
    /// Whether the `SO_REUSEADDR` socket option has been set.
    /// This option can only be set before calling `bind`.
    has_reuse_addr: Cell<bool>,
}

impl FileDescription for Socket {
    fn name(&self) -> &'static str {
        "socket"
    }

    fn destroy<'tcx>(
        self,
        _self_id: FdId,
        _communicate_allowed: bool,
        _ecx: &mut MiriInterpCx<'tcx>,
    ) -> InterpResult<'tcx, std::io::Result<()>>
    where
        Self: Sized,
    {
        interp_ok(Ok(()))
    }

    fn get_flags<'tcx>(&self, ecx: &mut MiriInterpCx<'tcx>) -> InterpResult<'tcx, Scalar> {
        let mut flags = ecx.eval_libc_i32("O_RDWR");

        if self.is_non_block.get() {
            flags |= ecx.eval_libc_i32("O_NONBLOCK");
        }

        interp_ok(Scalar::from_i32(flags))
    }

    fn set_flags<'tcx>(
        &self,
        mut _flag: i32,
        _ecx: &mut MiriInterpCx<'tcx>,
    ) -> InterpResult<'tcx, Scalar> {
        throw_unsup_format!("fcntl: socket flags aren't supported")
    }
}

impl<'tcx> EvalContextExt<'tcx> for crate::MiriInterpCx<'tcx> {}
pub trait EvalContextExt<'tcx>: crate::MiriInterpCxExt<'tcx> {
    /// For more information on the arguments see the socket manpage:
    /// <https://linux.die.net/man/2/socket>
    fn socket(
        &mut self,
        domain: &OpTy<'tcx>,
        type_: &OpTy<'tcx>,
        protocol: &OpTy<'tcx>,
    ) -> InterpResult<'tcx, Scalar> {
        let this = self.eval_context_mut();

        let domain = this.read_scalar(domain)?.to_i32()?;
        let mut flags = this.read_scalar(type_)?.to_i32()?;
        let protocol = this.read_scalar(protocol)?.to_i32()?;

        // Reject if isolation is enabled
        if let IsolatedOp::Reject(reject_with) = this.machine.isolated_op {
            this.reject_in_isolation("`socket`", reject_with)?;
            return this.set_last_error_and_return_i32(LibcError("EACCES"));
        }

        let mut is_sock_nonblock = false;

        // Interpret the flag. Every flag we recognize is "subtracted" from `flags`, so
        // if there is anything left at the end, that's an unsupported flag.
        if matches!(this.tcx.sess.target.os, Os::Linux | Os::Android | Os::FreeBsd) {
            // SOCK_NONBLOCK and SOCK_CLOEXEC only exist on Linux, Android and FreeBSD.
            let sock_nonblock = this.eval_libc_i32("SOCK_NONBLOCK");
            let sock_cloexec = this.eval_libc_i32("SOCK_CLOEXEC");
            if flags & sock_nonblock == sock_nonblock {
                is_sock_nonblock = true;
                flags &= !sock_nonblock;
            }
            if flags & sock_cloexec == sock_cloexec {
                // We don't support `exec` so we can ignore this.
                flags &= !sock_cloexec;
            }
        }

        let family = if domain == this.eval_libc_i32("AF_INET") {
            SocketFamily::IPv4
        } else if domain == this.eval_libc_i32("AF_INET6") {
            SocketFamily::IPv6
        } else {
            throw_unsup_format!(
                "socket: domain {:#x} is unsupported, only AF_INET and \
                                AF_INET6 are allowed.",
                domain
            );
        };

        if flags != this.eval_libc_i32("SOCK_STREAM") {
            throw_unsup_format!(
                "socket: type {:#x} is unsupported, only SOCK_STREAM, \
                                SOCK_CLOEXEC and SOCK_NONBLOCK are allowed",
                flags
            );
        }
        if protocol != 0 {
            throw_unsup_format!(
                "socket: socket protocol {protocol} is unsupported, \
                                only 0 is allowed"
            );
        }

        let fds = &mut this.machine.fds;
        let fd = fds.new_ref(Socket {
            family,
            socket_type: SocketType::Stream,
            state: RefCell::new(SocketState::Initial),
            is_non_block: Cell::new(is_sock_nonblock),
            has_no_sig_pipe: Cell::new(false),
            has_reuse_addr: Cell::new(false),
        });

        interp_ok(Scalar::from_i32(fds.insert(fd)))
    }

    fn bind(
        &mut self,
        socket: &OpTy<'tcx>,
        address: &OpTy<'tcx>,
        _address_len: &OpTy<'tcx>,
    ) -> InterpResult<'tcx, Scalar> {
        let this = self.eval_context_mut();

        let socket = this.read_scalar(socket)?.to_i32()?;
        let address = socket_address(address, "bind", this)?;

        // Reject if isolation is enabled
        if let IsolatedOp::Reject(reject_with) = this.machine.isolated_op {
            this.reject_in_isolation("`bind`", reject_with)?;
            return this.set_last_error_and_return_i32(LibcError("EACCES"));
        }

        // Get the file handle
        let Some(fd) = this.machine.fds.get(socket) else {
            return interp_ok(this.eval_libc("EBADF"));
        };

        let Some(socket) = fd.downcast::<Socket>() else {
            // Man page specifies to return ENOTSOCK if `fd` is not a socket.
            return interp_ok(this.eval_libc("ENOTSOCK"));
        };

        let mut state = socket.state.borrow_mut();

        // TODO: At the moment we do validation fo the parameters as good as we can. However,
        //       certain errors like EADDRINUSE won't be handled (for this we would need to check)
        //       whether the address is already in use on the current host. Should we "ignore" those
        //       errors as they will be thrown when calling `listen`?

        match *state {
            SocketState::Initial => {
                let address_family = match &address {
                    SocketAddr::V4(_) => SocketFamily::IPv4,
                    SocketAddr::V6(_) => SocketFamily::IPv6,
                };

                // The Dragonfly man pages don't mention an error for mismatched
                // socket and address families.
                if socket.family == address_family
                    || matches!(this.tcx.sess.target.os, Os::Dragonfly)
                {
                    *state = SocketState::Bind(address);
                } else {
                    // Attempted to bind an address from a family that doesn't match
                    // the family of the socket.
                    let err = if matches!(this.tcx.sess.target.os, Os::Linux | Os::Android) {
                        LibcError("EINVAL")
                    } else {
                        LibcError("EAFNOSUPPORT")
                    };
                    return this.set_last_error_and_return_i32(err);
                }
            }
            SocketState::Bind(_) | SocketState::TcpListener(_) => {
                // Linux and OpenBSD explicitly disallow binding an already bound socket
                // to another address. For the other targets it's protocol dependent and
                // thus we error.
                if matches!(this.tcx.sess.target.os, Os::Linux | Os::Android | Os::OpenBsd) {
                    return this.set_last_error_and_return_i32(LibcError("EINVAL"));
                } else {
                    throw_unsup_format!(
                        "bind: socket is already bound and binding a socket \
                                        multiple times is unsupported"
                    )
                }
            }
        }

        interp_ok(Scalar::from_i32(0))
    }

    fn listen(&mut self, socket: &OpTy<'tcx>, backlog: &OpTy<'tcx>) -> InterpResult<'tcx, Scalar> {
        let this = self.eval_context_mut();

        let socket = this.read_scalar(socket)?.to_i32()?;
        let backlog = this.read_scalar(backlog)?.to_i32()?;

        // Reject if isolation is enabled
        if let IsolatedOp::Reject(reject_with) = this.machine.isolated_op {
            this.reject_in_isolation("`bind`", reject_with)?;
            return this.set_last_error_and_return_i32(LibcError("EACCES"));
        }

        // Get the file handle
        let Some(fd) = this.machine.fds.get(socket) else {
            return interp_ok(this.eval_libc("EBADF"));
        };

        let Some(socket) = fd.downcast::<Socket>() else {
            // Man page specifies to return ENOTSOCK if `fd` is not a socket.
            return interp_ok(this.eval_libc("ENOTSOCK"));
        };

        // All targets except Horizon and Haiku use a 128 backlog in the standard library.
        let allowed_backlog = if matches!(this.tcx.sess.target.os, Os::Horizon) {
            20
        } else if matches!(this.tcx.sess.target.os, Os::Haiku) {
            32
        } else {
            128
        };

        // Only allow same backlog values as the standard library uses since the standard library
        // doesn't provide a way to use custom values.
        if backlog != allowed_backlog {
            throw_unsup_format!(
                "listen: backlog {backlog} is unsupported, only {allowed_backlog} is allowed"
            )
        }

        let mut state = socket.state.borrow_mut();

        match &*state {
            SocketState::Bind(socket_addr) =>
                match TcpListener::bind(socket_addr) {
                    Ok(listener) => {
                        *state = SocketState::TcpListener(listener);
                    }
                    Err(e) => return this.set_last_error_and_return_i32(e),
                },
            SocketState::Initial => {
                throw_unsup_format!(
                    "listen: listening on a socket which isn't bound is unsupported"
                )
            }
            SocketState::TcpListener(_) => {
                throw_unsup_format!("listen: listening on a socket multiple times is unsupported")
            }
        }

        interp_ok(Scalar::from_i32(0))
    }

    fn setsockopt(
        &mut self,
        socket: &OpTy<'tcx>,
        level: &OpTy<'tcx>,
        option_name: &OpTy<'tcx>,
        option_value: &OpTy<'tcx>,
        _option_len: &OpTy<'tcx>,
    ) -> InterpResult<'tcx, Scalar> {
        let this = self.eval_context_mut();

        let socket = this.read_scalar(socket)?.to_i32()?;
        let level = this.read_scalar(level)?.to_i32()?;
        let option_name = this.read_scalar(option_name)?.to_i32()?;

        // Reject if isolation is enabled
        if let IsolatedOp::Reject(reject_with) = this.machine.isolated_op {
            this.reject_in_isolation("`setsockopt`", reject_with)?;
            return this.set_last_error_and_return_i32(LibcError("EACCES"));
        }

        // Get the file handle
        let Some(fd) = this.machine.fds.get(socket) else {
            return interp_ok(this.eval_libc("EBADF"));
        };

        let Some(socket) = fd.downcast::<Socket>() else {
            // Man page specifies to return ENOTSOCK if `fd` is not a socket.
            return interp_ok(this.eval_libc("ENOTSOCK"));
        };

        let state = socket.state.borrow();

        // Set options on socket level, needed for
        // - [`TcpListener::bind`]: SO_REUSEADDR
        // - [`TcpListener::bind`]: SO_NOSIGPIPE no MacOS, FreeBSD, NetBSD and Dragonfly
        if level == this.eval_libc_i32("SOL_SOCKET") {
            let opt_so_reuseaddr = this.eval_libc_i32("SO_REUSEADDR");

            if matches!(this.tcx.sess.target.os, Os::MacOs | Os::NetBsd | Os::Dragonfly) {
                // SO_NOSIGPIPE only exists on MacOS, FreeBSD, NetBSD and Dragonfly.
                let opt_so_nosigpipe = this.eval_libc_i32("SO_NOSIGPIPE");

                if option_name == opt_so_nosigpipe {
                    let option_value =
                        this.deref_pointer_as(option_value, this.machine.layouts.i32)?;
                    let flag_set = this.read_scalar(&option_value)?.to_u32()? == 1;

                    if matches!(*state, SocketState::Initial) {
                        // This is set to 1 directly after calling `socket`.
                        // Since the standard library doesn't provide a way of setting this flag, we just ignore it.
                        if flag_set {
                            socket.has_no_sig_pipe.set(true);
                        } else {
                            throw_unsup_format!(
                                "setsockopt: option SO_NOSIGPIPE on level SOL_SOCKET can only be set to 1"
                            )
                        }
                    } else {
                        throw_unsup_format!(
                            "setsockopt: option SO_NOSIGPIPE on level SOL_SOCKET can only be set before \
                                                calling `bind` or `connect` on a socket"
                        )
                    }
                }
            }

            if option_name == opt_so_reuseaddr {
                let option_value = this.deref_pointer_as(option_value, this.machine.layouts.i32)?;
                let flag_set = this.read_scalar(&option_value)?.to_u32()? == 1;

                if matches!(*state, SocketState::Initial) {
                    // On non-windows targets this is set to 1 before calling `bind`.
                    // Since the standard library doesn't provide a way of setting this flag, we just ignore it.
                    if flag_set {
                        socket.has_reuse_addr.set(true);
                    } else {
                        throw_unsup_format!(
                            "setsockopt: option SO_REUSEADDR on level SOL_SOCKET can only be set to 1"
                        )
                    }
                } else {
                    throw_unsup_format!(
                        "setsockopt: option SO_REUSEADDR on level SOL_SOCKET can only be set before \
                                            calling `bind` on a socket"
                    )
                }
            } else {
                // TODO: This error message is not entirely correct as on MacOS and BSD targets
                //       also SO_NOSIGPIPE is allowed
                throw_unsup_format!(
                    "setsockopt: option {option_name} is unsupported for level SOL_SOCKET, only \
                                        SO_REUSEADDR is allowed",
                );
            }
        } else {
            throw_unsup_format!(
                "setsockopt: level {level} is unsupported, only SOL_SOCKET is allowed"
            );
        }

        interp_ok(Scalar::from_i32(0))
    }
}

fn socket_address<'tcx>(
    address: &OpTy<'tcx>,
    foreign_name: &'static str,
    this: &mut InterpCx<'tcx, MiriMachine<'tcx>>,
) -> InterpResult<'tcx, SocketAddr> {
    // Initially, treat address as generic sockaddr just to extract the family field.
    let sockaddr_layout = this.libc_ty_layout("sockaddr");
    let address = this.deref_pointer_as(address, sockaddr_layout)?;

    let family_field = this.project_field_named(&address, "sa_family")?;
    let family_layout = this.libc_ty_layout("sa_family_t");
    let family = this.read_scalar(&family_field)?.to_int(family_layout.size)?;

    // Depending on the family, decide whether it's IPv4 or IPv6 and use specialized layout
    // to extract address and port.
    let socket_addr = if family == this.eval_libc_i32("AF_INET").into() {
        let sockaddr_in_layout = this.libc_ty_layout("sockaddr_in");
        let address = address.offset(Size::ZERO, sockaddr_in_layout, this)?;

        let port_field = this.project_field_named(&address, "sin_port")?;
        let port = this.read_scalar(&port_field)?.to_u16()?;

        let addr_field = this.project_field_named(&address, "sin_addr")?;
        let s_addr_field = this.project_field_named(&addr_field, "s_addr")?;
        let addr_bits = this.read_scalar(&s_addr_field)?.to_u32()?;

        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_bits(addr_bits.to_be()), port.to_be()))
    } else if family == this.eval_libc_i32("AF_INET6").into() {
        let sockaddr_in6_layout = this.libc_ty_layout("sockaddr_in6");
        let address = address.offset(Size::ZERO, sockaddr_in6_layout, this)?;

        let port_field = this.project_field_named(&address, "sin6_port")?;
        let port = this.read_scalar(&port_field)?.to_u16()?;

        let addr_field = this.project_field_named(&address, "sin6_addr")?;
        let s_addr_field = this.project_field_named(&addr_field, "s6_addr")?.offset(
            Size::ZERO,
            this.machine.layouts.u128,
            this,
        )?;
        let addr_bits = this.read_scalar(&s_addr_field)?.to_u128()?;

        let flowinfo_field = this.project_field_named(&address, "sin6_flowinfo")?;
        let flowinfo = this.read_scalar(&flowinfo_field)?.to_u32()?;

        let scope_id_field = this.project_field_named(&address, "sin6_scope_id")?;
        let scope_id = this.read_scalar(&scope_id_field)?.to_u32()?;

        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from_bits(addr_bits.to_be()),
            port.to_be(),
            flowinfo,
            scope_id,
        ))
    } else {
        // Socket of other types shouldn't be created in a first place and
        // thus also no address family of another type should be supported.
        throw_unsup_format!(
            "{foreign_name}: address family {family} is unsupported, \
                            only AF_INET and AF_INET6 are allowed"
        );
    };

    interp_ok(socket_addr)
}
