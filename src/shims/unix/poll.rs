use crate::shims::unix::*;
use crate::*;

impl<'tcx> EvalContextExt<'tcx> for crate::MiriInterpCx<'tcx> {}
pub trait EvalContextExt<'tcx>: crate::MiriInterpCxExt<'tcx> {
    /// The `poll` shim is implemented using the epoll system because the epoll(7) man page states:
    /// "[...] when used as a level-triggered interface (the default, when EPOLLET is not specified),
    /// epoll is simply a faster poll(2) [...]".
    /// <https://man7.org/linux/man-pages/man7/epoll.7.html>
    fn poll(
        &mut self,
        fds: &OpTy<'tcx>,
        nfds: &OpTy<'tcx>,
        timeout: &OpTy<'tcx>,
        dest: &MPlaceTy<'tcx>,
    ) -> InterpResult<'tcx, Scalar> {
        let this = self.eval_context_mut();

        let nfds_layout = this.libc_ty_layout("nfds_t");
        let nfds: u64 = this.read_scalar(nfds)?.to_int(nfds_layout.size)?.try_into().unwrap();
        let timeout = this.read_scalar(timeout)?.to_i32()?;

        let fds_arr_layout = this.libc_array_ty_layout("pollfd", nfds);
        let fds_arr_mplace = this.deref_pointer_as(fds, fds_arr_layout)?;
        let mut fds = Vec::<(u64, MPlaceTy<'tcx>)>::new();

        let mut fds_arr_iter = this.project_array_fields(&fds_arr_mplace)?;

        let epfd_num = this.create_epoll_instance(/* flags */ 0)?;
        let Some(epfd) = this.machine.fds.get(epfd_num) else {
            return this.set_errno_and_return_neg1_i32(LibcError("EBADF"));
        };
        let epfd = epfd
            .downcast::<Epoll>()
            .expect("Newly created epfd should be an epoll file description");

        while let Some((_idx, pollfd)) = fds_arr_iter.next(this)? {
            let fd_field = this.project_field_named(&pollfd, "fd")?;
            let fd_num = this.read_scalar(&fd_field)?.to_i32()?;
            let Some(fd) = this.machine.fds.get(fd_num) else {
                return this.set_errno_and_return_neg1_i32(LibcError("EBADF"));
            };

            let events_field = this.project_field_named(&pollfd, "events")?;
            let events = this.read_scalar(&events_field)?.to_u16()?;
            let epoll_events = this.poll_events_to_epoll_events(events)?;

            let revents_field = this.project_field_named(&pollfd, "revents")?;
            // We initially zero every `revents` field because we later only
            // update the `revents` fields for the FDs which received an event.
            this.write_null(&revents_field)?;

            let data = u64::try_from(fd_num).unwrap();

            let result = this.register_epoll_interest(
                &epfd,
                /* reregister */ false,
                fd,
                fd_num,
                epoll_events,
                data,
            )?;

            match result {
                // Contrary to the epoll system, `poll` allows having the same fd multiple
                // times in the interest list. We thus treat EEXIST errors as successes.
                Ok(_) | Err(LibcError("EEXIST")) => fds.push((data, revents_field)),
                // The other possible errors from `epoll_ctl` are also valid errors for `poll`.
                Err(e) => return this.set_errno_and_return_neg1_i32(e),
            }
        }

        let dest = dest.clone();
        this.epoll_poll(
            epfd,
            nfds,
            timeout,
            callback!(
                @capture<'tcx> {
                    fds: Vec<(u64, MPlaceTy<'tcx>)>,
                    dest: MPlaceTy<'tcx>,
                }
                |this, ready_events: Vec<(u32, u64)>| {
                    let mut ready_count = 0i32;
                    for (events, data) in ready_events {
                        let poll_events = this.epoll_events_to_poll_events(events);
                        for (fd, revents_mplace) in fds.iter() {
                            if fd == &data {
                                this.write_scalar(Scalar::from_u16(poll_events), revents_mplace)?;
                                ready_count = ready_count.strict_add(1);
                            }
                        }
                    }
                    this.write_scalar(Scalar::from_i32(ready_count), &dest)
                }
            ),
        )?;

        interp_ok(Scalar::from_i32(0))
    }
}

impl<'tcx> EvalContextPrivExt<'tcx> for crate::MiriInterpCx<'tcx> {}
trait EvalContextPrivExt<'tcx>: crate::MiriInterpCxExt<'tcx> {
    /// Convert a poll events bitflag into an epoll events bitflag.
    /// This throws an unsupported error should `poll_interest` contain
    /// unsupported flags.
    fn poll_events_to_epoll_events(&self, mut poll_events: u16) -> InterpResult<'tcx, u32> {
        let this = self.eval_context_ref();

        let pollin = this.eval_libc_u16("POLLIN");
        let pollout = this.eval_libc_u16("POLLOUT");
        let pollerr = this.eval_libc_u16("POLLERR");
        let pollhup = this.eval_libc_u16("POLLHUP");
        let pollrdhup = this.eval_libc_u16("POLLRDHUP");

        let mut epoll_events = 0;

        if poll_events & pollin == pollin {
            epoll_events |= this.eval_libc_u32("EPOLLIN");
            poll_events &= !pollin;
        }
        if poll_events & pollout == pollout {
            epoll_events |= this.eval_libc_u32("EPOLLOUT");
            poll_events &= !pollout;
        }
        if poll_events & pollerr == pollerr {
            epoll_events |= this.eval_libc_u32("EPOLLERR");
            poll_events &= !pollerr;
        }
        if poll_events & pollhup == pollhup {
            epoll_events |= this.eval_libc_u32("EPOLLHUP");
            poll_events &= !pollhup;
        }
        if poll_events & pollrdhup == pollrdhup {
            epoll_events |= this.eval_libc_u32("EPOLLRDHUP");
            poll_events &= !pollrdhup;
        }
        if poll_events != 0 {
            throw_unsup_format!(
                "poll: poll event {poll_events:#x} is unsupported. Only POLLIN, \
                POLLOUT, POLLERR, POLLHUP, and POLLRDHUP are supported."
            );
        }

        interp_ok(epoll_events)
    }

    /// Convert an epoll events bitflag into a poll events bitflag.
    /// Because the `epoll_events` should only contain events for
    /// bitflags created using [`Self::poll_events_to_epoll_events`],
    /// this panics if it contains invalid events.
    fn epoll_events_to_poll_events(&self, mut epoll_events: u32) -> u16 {
        let this = self.eval_context_ref();
        let epollin = this.eval_libc_u32("EPOLLIN");
        let epollout = this.eval_libc_u32("EPOLLOUT");
        let epollerr = this.eval_libc_u32("EPOLLERR");
        let epollhup = this.eval_libc_u32("EPOLLHUP");
        let epollrdhup = this.eval_libc_u32("EPOLLRDHUP");

        let mut poll_events = 0;

        if epoll_events & epollin == epollin {
            poll_events |= this.eval_libc_u16("POLLIN");
            epoll_events &= !epollin;
        }
        if epoll_events & epollout == epollout {
            poll_events |= this.eval_libc_u16("POLLOUT");
            epoll_events &= !epollout;
        }
        if epoll_events & epollerr == epollerr {
            poll_events |= this.eval_libc_u16("POLLERR");
            epoll_events &= !epollerr;
        }
        if epoll_events & epollhup == epollhup {
            poll_events |= this.eval_libc_u16("POLLHUP");
            epoll_events &= !epollhup;
        }
        if epoll_events & epollrdhup == epollrdhup {
            poll_events |= this.eval_libc_u16("POLLRDHUP");
            epoll_events &= !epollrdhup;
        }
        if epoll_events != 0 {
            // We directly panic here instead of throwing an unsupported error, because this violates
            // our assumption that `epoll_events` must only contain events matching bitflags created
            // using `poll_events_to_epoll_events`.
            panic!(
                "`epoll_events` contained an unsupported event which cannot be created \
                using `poll_events_to_epoll_events`"
            );
        }

        poll_events
    }
}
