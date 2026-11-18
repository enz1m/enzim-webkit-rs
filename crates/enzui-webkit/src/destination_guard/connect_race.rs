use super::*;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socket_with};
use std::time::Instant;

const MAX_CANDIDATES: usize = 16;
#[cfg(test)]
mod tests;

const FALLBACK_DELAY: Duration = Duration::from_millis(250);

// Every answer is validated before this bounded, family-interleaved subset is made.
pub(super) fn candidates(resolved: &[SocketAddr]) -> Vec<SocketAddr> {
    let Some(first) = resolved.first() else {
        return Vec::new();
    };
    let mut selected: Vec<SocketAddr> = Vec::with_capacity(resolved.len().min(MAX_CANDIDATES));
    let mut prefer_v4 = first.is_ipv4();
    while selected.len() < MAX_CANDIDATES {
        let next = resolved
            .iter()
            .find(|address| address.is_ipv4() == prefer_v4 && !selected.contains(*address))
            .or_else(|| resolved.iter().find(|address| !selected.contains(*address)));
        let Some(&next) = next else { break };
        selected.push(next);
        prefer_v4 = !next.is_ipv4();
    }
    selected
}

fn start(address: SocketAddr) -> std::io::Result<(TcpStream, bool)> {
    let family = if address.is_ipv4() {
        AddressFamily::INET
    } else {
        AddressFamily::INET6
    };
    let descriptor = socket_with(
        family,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        Some(rustix::net::ipproto::TCP),
    )?;
    let connected = match rustix::net::connect(&descriptor, &address) {
        Ok(()) => true,
        Err(rustix::io::Errno::INPROGRESS) => false,
        Err(error) => return Err(error.into()),
    };
    Ok((TcpStream::from(descriptor), connected))
}

pub(super) fn connect(
    candidates: &[SocketAddr],
    timeout: Duration,
    attempt: &mut dyn FnMut(),
) -> std::io::Result<(TcpStream, SocketAddr)> {
    let started = Instant::now();
    let candidates = &candidates[..candidates.len().min(MAX_CANDIDATES)];
    if candidates.len() == 1 && !timeout.is_zero() {
        attempt();
        return TcpStream::connect_timeout(&candidates[0], timeout)
            .map(|stream| (stream, candidates[0]));
    }
    let mut pending = Vec::<(TcpStream, SocketAddr)>::with_capacity(candidates.len());
    let mut next = 0;
    let mut next_start = Duration::ZERO;
    let mut error = std::io::Error::from(std::io::ErrorKind::NotFound);
    loop {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        if next < candidates.len() && (pending.is_empty() || elapsed >= next_start) {
            let address = candidates[next];
            next += 1;
            attempt();
            match start(address) {
                Ok((stream, true)) => {
                    stream.set_nonblocking(false)?;
                    return Ok((stream, address));
                }
                Ok((stream, false)) => pending.push((stream, address)),
                Err(failure) => error = failure,
            }
            next_start = started.elapsed() + FALLBACK_DELAY;
        }
        if pending.is_empty() {
            if next == candidates.len() {
                return Err(error);
            }
            continue;
        }
        let mut wait = timeout.saturating_sub(started.elapsed());
        if next < candidates.len() {
            wait = wait.min(next_start.saturating_sub(started.elapsed()));
        }
        let flags: [PollFlags; MAX_CANDIDATES] = {
            let mut descriptors: [PollFd<'_>; MAX_CANDIDATES] =
                std::array::from_fn(|_| PollFd::new(&pending[0].0, PollFlags::OUT));
            for (descriptor, (stream, _)) in descriptors.iter_mut().zip(&pending) {
                *descriptor = PollFd::new(stream, PollFlags::OUT);
            }
            let timeout = Timespec::try_from(wait)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
            match poll(&mut descriptors[..pending.len()], Some(&timeout)) {
                Ok(_) => std::array::from_fn(|index| descriptors[index].revents()),
                Err(rustix::io::Errno::INTR) => continue,
                Err(failure) => return Err(failure.into()),
            }
        };
        for index in (0..pending.len()).rev() {
            if flags[index].is_empty() {
                continue;
            }
            match pending[index].0.take_error() {
                Ok(None) if flags[index].contains(PollFlags::OUT) => {
                    let (stream, address) = pending.swap_remove(index);
                    stream.set_nonblocking(false)?;
                    return Ok((stream, address));
                }
                Ok(Some(failure)) | Err(failure) => error = failure,
                Ok(None) => error = std::io::ErrorKind::ConnectionAborted.into(),
            }
            pending.swap_remove(index);
            // A refused candidate need not delay another approved address.
            next_start = started.elapsed();
        }
        if pending.is_empty() && next == candidates.len() {
            return Err(error);
        }
    }
}
