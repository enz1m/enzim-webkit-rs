use super::*;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

const MAX_TUNNELS: usize = 128;
const MAX_TUNNELS_PER_DESTINATION: usize = MAX_TUNNELS / 2;
const BUFFER_BYTES: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

mod loopback;

#[cfg(test)]
mod tests;

#[cfg(test)]
std::thread_local! {
    static READ_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) struct TunnelRelay {
    pub sender: TunnelSender,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[derive(Clone)]
pub(super) struct TunnelSender {
    sender: SyncSender<RelayTunnel>,
    capacity: Arc<Mutex<Capacity>>,
    wake: Arc<UnixStream>,
    loopback_records: bool,
}

#[derive(Default)]
struct Capacity {
    total: usize,
    destinations: HashMap<IpAddr, usize>,
}

pub(super) struct Permit {
    capacity: Arc<Mutex<Capacity>>,
    destination: IpAddr,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut capacity = self
            .capacity
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        capacity.total -= 1;
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            capacity.destinations.entry(self.destination)
        {
            *entry.get_mut() -= 1;
            if *entry.get() == 0 {
                entry.remove();
            }
        }
    }
}

impl TunnelRelay {
    pub fn start(shared: Arc<Shared>) -> std::io::Result<Self> {
        let loopback_records = loopback::needs_records();
        let (sender, receiver) = sync_channel(MAX_TUNNELS);
        let (wake, reader) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        reader.set_nonblocking(true)?;
        let thread = std::thread::Builder::new()
            .name("enzui-destination-tunnels".into())
            .spawn(move || run(receiver, &shared, reader))?;
        Ok(Self {
            sender: TunnelSender {
                sender,
                capacity: Arc::new(Mutex::new(Capacity::default())),
                wake: Arc::new(wake),
                loopback_records,
            },
            thread: Some(thread),
        })
    }

    pub fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.sender.notify();
            let _ = thread.join();
        }
    }
}

impl TunnelSender {
    fn notify(&self) {
        // A full nonblocking wake socket already has a pending notification.
        let mut writer = &*self.wake;
        loop {
            match writer.write(&[1]) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                _ => break,
            }
        }
    }

    pub fn reserve(&self, address: IpAddr) -> Option<Permit> {
        let destination = address.to_canonical();
        let mut capacity = self
            .capacity
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if capacity.total == MAX_TUNNELS {
            return None;
        }
        let used = capacity.destinations.entry(destination).or_default();
        if *used == MAX_TUNNELS_PER_DESTINATION {
            return None;
        }
        *used += 1;
        capacity.total += 1;
        Some(Permit {
            capacity: self.capacity.clone(),
            destination,
        })
    }

    pub fn relay(
        &self,
        client: TcpStream,
        upstream: TcpStream,
        lease: ConnectionLease,
        permit: Permit,
    ) {
        // TLS records and interactive messages must not wait for delayed ACKs on either hop.
        if client.set_nodelay(true).is_err()
            || upstream.set_nodelay(true).is_err()
            || client.set_nonblocking(true).is_err()
            || upstream.set_nonblocking(true).is_err()
        {
            return;
        }
        let tunnel = self.tunnel(client, upstream, lease, permit);
        // Admission counts both queued and active tunnels, so the queue cannot
        // fill while a permit is held. A stopped relay closes this connection.
        if self.sender.try_send(RelayTunnel::Tcp(tunnel)).is_ok() {
            self.notify();
        }
    }

    fn tunnel(
        &self,
        client: TcpStream,
        upstream: TcpStream,
        lease: ConnectionLease,
        permit: Permit,
    ) -> Tunnel {
        // An upgraded exchange with an allowed local origin also crosses loopback.
        let upload_records =
            self.loopback_records && loopback::reaches_peer_over_loopback(&upstream);
        Tunnel {
            client,
            upstream,
            _lease: lease,
            _permit: permit,
            upload: Direction::new().in_records(upload_records),
            download: Direction::new().in_records(self.loopback_records),
            last_activity: Instant::now(),
        }
    }

    pub fn relay_datagram(
        &self,
        client: TcpStream,
        upstream: std::net::UdpSocket,
        lease: ConnectionLease,
        permit: Permit,
        buffered: &[u8],
    ) -> std::io::Result<()> {
        client.set_nonblocking(true)?;
        upstream.set_nonblocking(true)?;
        let mut capsules = super::datagrams::Capsules::new();
        capsules.push(buffered)?;
        let mut packet = Vec::new();
        let pending = capsules.take_into(&mut packet)?;
        let tunnel = DatagramTunnel {
            client,
            upstream,
            _lease: lease,
            _permit: permit,
            capsules,
            packet,
            pending,
            output: Vec::new(),
            written: 0,
            received: vec![0; 65_536].into_boxed_slice(),
            eof: false,
            last_activity: Instant::now(),
        };
        self.sender
            .try_send(RelayTunnel::Datagram(Box::new(tunnel)))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        self.notify();
        Ok(())
    }
}

enum RelayTunnel {
    Tcp(Tunnel),
    Datagram(Box<DatagramTunnel>),
}

impl RelayTunnel {
    fn interests(&self) -> [PollFlags; 2] {
        match self {
            Self::Tcp(t) => t.interests(),
            Self::Datagram(t) => t.interests(),
        }
    }
    fn client(&self) -> &TcpStream {
        match self {
            Self::Tcp(t) => &t.client,
            Self::Datagram(t) => &t.client,
        }
    }
    fn upstream(&self) -> BorrowedFd<'_> {
        match self {
            Self::Tcp(t) => t.upstream.as_fd(),
            Self::Datagram(t) => t.upstream.as_fd(),
        }
    }
    fn step(&mut self, client: PollFlags, upstream: PollFlags) -> std::io::Result<bool> {
        match self {
            Self::Tcp(t) => t.step(client, upstream),
            Self::Datagram(t) => t.step(client, upstream),
        }
    }
}

struct DatagramTunnel {
    client: TcpStream,
    upstream: std::net::UdpSocket,
    _lease: ConnectionLease,
    _permit: Permit,
    capsules: super::datagrams::Capsules,
    packet: Vec<u8>,
    pending: bool,
    output: Vec<u8>,
    written: usize,
    received: Box<[u8]>,
    eof: bool,
    last_activity: Instant,
}

impl DatagramTunnel {
    fn interests(&self) -> [PollFlags; 2] {
        let mut client = PollFlags::empty();
        let mut upstream = PollFlags::empty();
        if !self.eof && !self.pending && self.capsules.available() != 0 {
            client |= PollFlags::IN;
        }
        if self.output.is_empty() {
            upstream |= PollFlags::IN;
        } else {
            client |= PollFlags::OUT;
        }
        if self.pending {
            upstream |= PollFlags::OUT;
        }
        [client, upstream]
    }

    fn step(&mut self, client: PollFlags, upstream: PollFlags) -> std::io::Result<bool> {
        if (client | upstream).intersects(PollFlags::ERR | PollFlags::NVAL) {
            return Ok(false);
        }
        let mut progress = false;
        for _ in 0..4 {
            let mut advanced = false;
            if !self.pending {
                self.pending = self.capsules.take_into(&mut self.packet)?;
            }
            if self.pending {
                match self.upstream.send(&self.packet) {
                    Ok(count) if count == self.packet.len() => {
                        self.pending = false;
                        advanced = true;
                    }
                    Ok(_) => return Ok(false),
                    Err(error) if retry(&error) => (),
                    Err(error)
                        if error.raw_os_error()
                            == Some(rustix::io::Errno::MSGSIZE.raw_os_error()) =>
                    {
                        self.pending = false;
                        advanced = true;
                    }
                    Err(error) => return Err(error),
                }
            }
            if !self.eof && !self.pending && client.intersects(PollFlags::IN | PollFlags::HUP) {
                let mut bytes = [0; BUFFER_BYTES];
                let length = bytes.len().min(self.capsules.available());
                if length != 0 {
                    match self.client.read(&mut bytes[..length]) {
                        Ok(0) => self.eof = true,
                        Ok(count) => {
                            self.capsules.push(&bytes[..count])?;
                            advanced = true;
                        }
                        Err(error) if retry(&error) => (),
                        Err(error) => return Err(error),
                    }
                }
            }
            if self.output.is_empty() && upstream.contains(PollFlags::IN) {
                match self.upstream.recv(&mut self.received) {
                    Ok(count) => {
                        super::datagrams::encode(&self.received[..count], &mut self.output);
                        self.written = 0;
                        advanced = true;
                    }
                    Err(error) if retry(&error) => (),
                    Err(error) => return Err(error),
                }
            }
            if !self.output.is_empty() {
                match self.client.write(&self.output[self.written..]) {
                    Ok(0) => return Ok(false),
                    Ok(count) => {
                        self.written += count;
                        if self.written == self.output.len() {
                            self.output.clear();
                            self.written = 0;
                        }
                        advanced = true;
                    }
                    Err(error) if retry(&error) => (),
                    Err(error) => return Err(error),
                }
            }
            progress |= advanced;
            if !advanced {
                break;
            }
        }
        if !self.pending {
            self.pending = self.capsules.take_into(&mut self.packet)?;
        }
        if progress {
            self.last_activity = Instant::now();
        }
        Ok(!(self.eof && !self.pending && self.output.is_empty())
            && self.last_activity.elapsed() < RELAY_IO_TIMEOUT)
    }
}

fn retry(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    )
}

struct Tunnel {
    client: TcpStream,
    upstream: TcpStream,
    _lease: ConnectionLease,
    _permit: Permit,
    upload: Direction,
    download: Direction,
    last_activity: Instant,
}

struct Direction {
    bytes: Box<[u8]>,
    start: usize,
    end: usize,
    eof: bool,
    shutdown_sent: bool,
    records: bool,
}

#[derive(Default)]
struct ReadProgress {
    advanced: bool,
    ready: bool,
}

impl Direction {
    fn new() -> Self {
        Self {
            bytes: vec![0; BUFFER_BYTES].into_boxed_slice(),
            start: 0,
            end: 0,
            eof: false,
            shutdown_sent: false,
            records: false,
        }
    }

    /// Writes this direction as loopback records, see `loopback::send_record`.
    fn in_records(mut self, enabled: bool) -> Self {
        self.records = enabled;
        self
    }

    fn readable(&self) -> bool {
        !self.eof && self.end - self.start < self.bytes.len()
    }

    fn pending(&self) -> bool {
        self.end != self.start
    }

    fn read(&mut self, source: &mut TcpStream) -> std::io::Result<ReadProgress> {
        if !self.readable() {
            return Ok(ReadProgress::default());
        }
        if self.end == self.bytes.len() {
            self.bytes.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        #[cfg(test)]
        READ_ATTEMPTS.set(READ_ATTEMPTS.get() + 1);
        let available = self.bytes.len() - self.end;
        match source.read(&mut self.bytes[self.end..]) {
            Ok(0) => {
                self.eof = true;
                Ok(ReadProgress::default())
            }
            Ok(count) => {
                self.end += count;
                Ok(ReadProgress {
                    advanced: true,
                    // Level-triggered polling rediscovers bytes arriving after a short read.
                    ready: count == available,
                })
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(ReadProgress::default())
            }
            Err(error) => Err(error),
        }
    }

    fn write(&mut self, destination: &mut TcpStream) -> std::io::Result<bool> {
        let mut progress = false;
        while self.pending() {
            let pending = &self.bytes[self.start..self.end];
            let written = if self.records {
                loopback::send_record(destination, pending)
            } else {
                destination.write(pending)
            };
            match written {
                Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
                Ok(count) => {
                    self.start += count;
                    if self.start == self.end {
                        self.start = 0;
                        self.end = 0;
                    }
                    progress = true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(error) => return Err(error),
            }
            // One buffer is one write, or several records.
            if !self.records {
                break;
            }
        }
        if self.eof && !self.pending() && !self.shutdown_sent {
            destination.shutdown(Shutdown::Write)?;
            self.shutdown_sent = true;
        }
        Ok(progress)
    }
}

impl Tunnel {
    fn interests(&self) -> [PollFlags; 2] {
        let mut client = PollFlags::empty();
        let mut upstream = PollFlags::empty();
        if self.upload.readable() {
            client |= PollFlags::IN;
        }
        if self.download.readable() {
            upstream |= PollFlags::IN;
        }
        if self.download.pending() {
            client |= PollFlags::OUT;
        }
        if self.upload.pending() {
            upstream |= PollFlags::OUT;
        }
        [client, upstream]
    }

    fn step(&mut self, client: PollFlags, upstream: PollFlags) -> std::io::Result<bool> {
        if (client | upstream).intersects(PollFlags::ERR | PollFlags::NVAL) {
            return Ok(false);
        }
        let mut progress = false;
        let mut upload_ready = client.intersects(PollFlags::IN | PollFlags::HUP);
        let mut download_ready = upstream.intersects(PollFlags::IN | PollFlags::HUP);
        // Four passes drain ready bursts while bounding each direction to 64 KiB per turn.
        for _ in 0..4 {
            let mut advanced = false;
            if upload_ready {
                let read = self.upload.read(&mut self.client)?;
                advanced |= read.advanced;
                upload_ready = read.ready;
            }
            if download_ready {
                let read = self.download.read(&mut self.upstream)?;
                advanced |= read.advanced;
                download_ready = read.ready;
            }
            advanced |= self.upload.write(&mut self.upstream)?;
            advanced |= self.download.write(&mut self.client)?;
            progress |= advanced;
            if !advanced {
                break;
            }
        }
        if progress {
            self.last_activity = Instant::now();
        }
        Ok(!(self.upload.shutdown_sent && self.download.shutdown_sent)
            && self.last_activity.elapsed() < RELAY_IO_TIMEOUT)
    }
}

fn poll_ready<const CAPACITY: usize>(
    tunnels: &[RelayTunnel],
    wake: &UnixStream,
    readiness: &mut [PollFlags],
    timeout: &Timespec,
) -> rustix::io::Result<bool> {
    // Admission bounds the descriptor count; scratch storage needs no heap allocations.
    let mut descriptors: [PollFd<'_>; CAPACITY] =
        std::array::from_fn(|_| PollFd::new(wake, PollFlags::IN));
    let mut indices = [0; CAPACITY];
    let mut count = 1;
    for (index, tunnel) in tunnels.iter().enumerate() {
        let [client, upstream] = tunnel.interests();
        // poll reports HUP even with no requested events. Omit an
        // exhausted read side until it has pending output to avoid spin.
        if !client.is_empty() {
            descriptors[count] = PollFd::new(tunnel.client(), client);
            indices[count] = index * 2;
            count += 1;
        }
        if !upstream.is_empty() {
            descriptors[count] = PollFd::from_borrowed_fd(tunnel.upstream(), upstream);
            indices[count] = index * 2 + 1;
            count += 1;
        }
    }
    poll(&mut descriptors[..count], Some(timeout))?;
    let notified = descriptors[0].revents().contains(PollFlags::IN);
    readiness.fill(PollFlags::empty());
    for (descriptor, index) in descriptors[1..count].iter().zip(&indices[1..count]) {
        readiness[*index] = descriptor.revents();
    }
    Ok(notified)
}

fn run(receiver: Receiver<RelayTunnel>, shared: &Shared, mut wake: UnixStream) {
    let mut tunnels: Vec<RelayTunnel> = Vec::with_capacity(MAX_TUNNELS);
    let timeout = Timespec::try_from(POLL_INTERVAL).expect("bounded poll interval");
    let mut readiness = [PollFlags::empty(); MAX_TUNNELS * 2];
    while !shared.stop.load(Ordering::SeqCst) {
        tunnels.extend(receiver.try_iter());
        let active_readiness = &mut readiness[..tunnels.len() * 2];
        let result = if tunnels.len() <= 8 {
            poll_ready::<17>(&tunnels, &wake, active_readiness, &timeout)
        } else {
            poll_ready::<{ MAX_TUNNELS * 2 + 1 }>(&tunnels, &wake, active_readiness, &timeout)
        };
        let notified = match result {
            Ok(notified) => notified,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return,
        };
        if notified {
            let mut bytes = [0; MAX_TUNNELS];
            // One bounded read coalesces notifications without starving ready tunnels.
            if wake.read(&mut bytes).is_ok() {
                #[cfg(test)]
                shared.relay_wakes.fetch_add(1, Ordering::SeqCst);
            }
        }
        for index in (0..tunnels.len()).rev() {
            if !tunnels[index]
                .step(readiness[index * 2], readiness[index * 2 + 1])
                .unwrap_or(false)
            {
                tunnels.swap_remove(index);
            }
        }
    }
}
