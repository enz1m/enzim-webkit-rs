//! WebProcess sandbox preflight and attestation.
//!
//! [`preflight`] refuses to start a native session when the environment would
//! weaken WebKit's bubblewrap sandbox. Attestation reports whether launched
//! renderers run in their own mount, PID and user namespaces.
//!

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;

#[cfg(any(feature = "wpe", test))]
mod flatpak;
#[cfg(feature = "wpe")]
pub(crate) use flatpak::application_id as flatpak_application_id;
#[cfg(feature = "wpe")]
pub(crate) use flatpak::attest_renderer as attest_flatpak_renderer;

#[cfg(any(feature = "wpe", test))]
pub(crate) mod process_liveness;

/// The one environment variable WPE 2.52 still honours to switch the
/// WebProcess sandbox off entirely.
pub const DISABLE_VARIABLE: &str = "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS";

/// Re-allows `ptrace`/`personality`/`perf_event_open` inside the sandbox, binds
/// `/bin` and `/usr/bin`, and makes WebKit skip `--unshare-pid`.
pub const DEBUG_PERMISSIONS_VARIABLE: &str = "WEBKIT_ENABLE_DEBUG_PERMISSIONS_IN_SANDBOX";

/// Enables the remote inspector, which makes WebKit skip `--unshare-net` and
/// mark the sandbox instance as network-shared.
pub const INSPECTOR_VARIABLE: &str = "WEBKIT_INSPECTOR_SERVER";

/// Starts the remote inspector's HTTP server, an endpoint other local
/// processes can reach. The local inspector needs neither variable.
pub const INSPECTOR_HTTP_VARIABLE: &str = "WEBKIT_INSPECTOR_HTTP_SERVER";

/// Flatpak marker file: WebKit skips its own bubblewrap launcher when present.
pub const FLATPAK_MARKER: &str = "/.flatpak-info";

/// Container marker file: WebKit probes `bwrap` and disables sandboxing if the
/// probe fails.
pub const CONTAINER_MARKER: &str = "/run/.containerenv";

/// The three variables WebKit requires together before believing it is in Snap.
pub const SNAP_VARIABLES: [&str; 3] = ["SNAP", "SNAP_NAME", "SNAP_REVISION"];

/// The `/proc/<pid>/comm` value of a WPE WebProcess.
///
/// `comm` is truncated by the kernel to 15 bytes; this name is 13, so it
/// arrives intact. The sibling `WPENetworkProcess` truncates to
/// `WPENetworkProce` - and is deliberately not matched here, because WebKit
/// does not sandbox the network process. Matching it would make an honest
/// attestation report an unconfined process and fail a correct build.
pub const WEB_PROCESS_COMM: &str = "WPEWebProcess";

/// The `/proc/<pid>/comm` value of the WPE GPU process, 13 bytes as well.
///
/// The GPU process runs commands from web content, so when it exists it must
/// be isolated like a WebProcess.
pub const GPU_PROCESS_COMM: &str = "WPEGPUProcess";

/// The `comm` of the bubblewrap launcher WebKit execs between this code and the
/// renderer.
///
/// `comm` is not an identity: it is the basename of whatever file was
/// exec'd (and a process may rewrite it). It is used only to *find* candidate
/// ancestors; the candidate is then checked against
/// [`TRUSTED_LAUNCHER_PATHS`] by device+inode in
/// [`verify_launcher_executable`], so a copy of some other binary named
/// `bwrap` cannot launder a renderer into an attestation.
pub const BWRAP_COMM: &str = "bwrap";

/// The filesystem locations a *trusted* bubblewrap binary may live at.
///
/// Identity is compared by `(device, inode)` of the file `/proc/<pid>/exe`
/// resolves to, not by path text: a bind-mount, a symlink or a hard link to the
/// real binary all compare equal, while a copy - the forgery - does not.
pub const TRUSTED_LAUNCHER_PATHS: [&str; 3] =
    ["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"];

/// A file's `(device, inode)` pair - what makes two paths the same file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
}

/// The identity of the file at `path`, or `None` when it cannot be stat'd.
#[must_use]
pub fn file_identity(path: &str) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).ok()?;
    Some(FileIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

/// Every trusted launcher binary that exists on this host.
///
/// An empty result is a refusal condition, not a pass: a host with no
/// bubblewrap cannot sandbox a WebProcess at all.
#[must_use]
pub fn trusted_launcher_identities() -> Vec<FileIdentity> {
    let mut out: Vec<FileIdentity> = Vec::new();
    for path in TRUSTED_LAUNCHER_PATHS {
        if let Some(id) = file_identity(path)
            && !out.contains(&id)
        {
            out.push(id);
        }
    }
    out
}

/// Check that `pid` is really executing a trusted bubblewrap binary.
///
/// Reads `/proc/<pid>/exe` - which the kernel maintains, and which a process
/// cannot rewrite the way it can rewrite `comm` - and compares the file it
/// resolves to against [`trusted_launcher_identities`] by device+inode.
///
/// # Errors
///
/// A human-readable reason. Every uncertainty (unreadable link, no trusted
/// binary installed, a different file) is an error, never a pass.
pub fn verify_launcher_executable(pid: u32) -> Result<FileIdentity, String> {
    use std::os::unix::fs::MetadataExt;
    let trusted = trusted_launcher_identities();
    if trusted.is_empty() {
        return Err(format!(
            "no trusted bubblewrap binary exists at any of {TRUSTED_LAUNCHER_PATHS:?}, \
             so no launcher can be verified on this host"
        ));
    }
    let exe = format!("/proc/{pid}/exe");
    let meta = fs::metadata(&exe).map_err(|e| format!("{exe}: {e}"))?;
    let found = FileIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    };
    if trusted.contains(&found) {
        Ok(found)
    } else {
        let target = fs::read_link(&exe)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|e| format!("<unreadable: {e}>"));
        Err(format!(
            "{exe} -> {target} (dev {}, ino {}) is not any trusted bwrap in \
             {TRUSTED_LAUNCHER_PATHS:?}",
            found.dev, found.ino
        ))
    }
}

/// Which container WebKit believes it is inside, and therefore will not
/// bubblewrap in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    /// `/.flatpak-info` exists.
    Flatpak,
    /// All of [`SNAP_VARIABLES`] are set.
    Snap,
    /// `/run/.containerenv` exists, or either filesystem marker could not be
    /// probed. WebKit probes `bwrap` in an unsupported container and disables
    /// sandboxing when the probe fails; this code cannot see the outcome from outside,
    /// and an indeterminate marker must not be mistaken for absence.
    UnverifiedContainer,
}

/// Whether the host has explicitly taken responsibility for an outer sandbox.
///
/// This is a typed, in-code decision, not an environment variable, because
/// an environment opt-out of a sandbox check is the same class of defect as
/// the sandbox opt-out it is guarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterSandbox {
    /// The default: a container in which WebKit will not bubblewrap is a
    /// refusal.
    Rejected,
    /// The host states that an outer sandbox (Flatpak/Snap/container policy)
    /// confines this whole process, so WebKit skipping its inner sandbox is
    /// acceptable. Environment variables that *weaken* the sandbox are still
    /// refused; this only accepts the container itself.
    AcceptedByHost,
}

/// Why a native session must not start.
///
/// `#[non_exhaustive]`: a future WPE release can add another way to weaken the
/// sandbox, and adding the variant must not be a breaking change that pressures
/// the next author into omitting it. Match with a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SandboxRefusal {
    /// [`DISABLE_VARIABLE`] is present in the environment.
    ///
    /// Presence, not truthiness: WebKit disables the sandbox for every value
    /// except exactly `"0"`, and `=0` is precisely what someone would type
    /// while turning it off. Being stricter than the engine can only refuse a
    /// session that would have been sandboxed - it can never admit one that
    /// would not.
    DisableVariablePresent {
        /// The value as found, lossily decoded so it can be printed. See
        /// `lossy`.
        value: String,
        /// The raw value was not valid UTF-8. The refusal does not depend on
        /// decoding: the check is presence of the variable in the real
        /// environment, which is where WebKit reads it from as raw bytes.
        lossy: bool,
    },
    /// [`DEBUG_PERMISSIONS_VARIABLE`] is present: the renderer would keep
    /// `ptrace`/`perf_event_open` and lose `--unshare-pid`.
    DebugPermissionsVariablePresent {
        /// The value as found (lossy).
        value: String,
    },
    /// [`INSPECTOR_VARIABLE`] is present: the renderer would keep host network
    /// access, and production sessions expose no remote inspector.
    RemoteInspectorVariablePresent {
        /// The value as found (lossy).
        value: String,
    },
    /// [`INSPECTOR_HTTP_VARIABLE`] is present: WebKit would serve the remote
    /// inspector over HTTP to other processes.
    RemoteInspectorHttpVariablePresent {
        /// The value as found (lossy).
        value: String,
    },
    /// WebKit will not use its bubblewrap launcher in this container, and the
    /// host has not accepted responsibility for an outer sandbox.
    BubblewrapNotUsedInContainer {
        /// Which container was detected.
        container: ContainerKind,
    },
}

impl std::fmt::Display for SandboxRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxRefusal::DisableVariablePresent { value, lossy } => write!(
                f,
                "refusing to start a native WebKit session: {DISABLE_VARIABLE}={value:?}\
                 {} is set, which disables WebProcess sandboxing. Native sessions require the \
                 sandbox to stay enabled; unset the variable or run the mock backend.",
                if *lossy { " (not valid UTF-8)" } else { "" }
            ),
            SandboxRefusal::DebugPermissionsVariablePresent { value } => write!(
                f,
                "refusing to start a native WebKit session: \
                 {DEBUG_PERMISSIONS_VARIABLE}={value:?} is set, which re-allows \
                 ptrace/personality/perf_event_open in the WebProcess and drops \
                 --unshare-pid. Unset it."
            ),
            SandboxRefusal::RemoteInspectorVariablePresent { value } => write!(
                f,
                "refusing to start a native WebKit session: {INSPECTOR_VARIABLE}={value:?} \
                 is set, which drops --unshare-net from the WebProcess sandbox. \
                 Native sessions expose no remote inspector; use the local inspector \
                 and unset it."
            ),
            SandboxRefusal::RemoteInspectorHttpVariablePresent { value } => write!(
                f,
                "refusing to start a native WebKit session: {INSPECTOR_HTTP_VARIABLE}={value:?} \
                 is set, which serves the remote inspector over HTTP. Native sessions \
                 expose no remote inspector; use the local inspector and unset it."
            ),
            SandboxRefusal::BubblewrapNotUsedInContainer { container } => write!(
                f,
                "refusing to start a native WebKit session: this process looks like \
                 {container:?}, where WPE does not use its bubblewrap launcher, so the \
                 WebProcess would run unconfined by WebKit. If an outer sandbox confines \
                 this process, the host must say so in code with \
                 OuterSandbox::AcceptedByHost."
            ),
        }
    }
}

impl std::error::Error for SandboxRefusal {}

/// Result of probing a filesystem marker used by WebKit's container checks.
///
/// An I/O failure is not absence. Keeping it typed prevents callers and test
/// fixtures from accidentally turning an unreadable or malformed marker path
/// into permission to start an unverified native renderer.
#[derive(Debug)]
pub enum MarkerPresence {
    /// The marker has a directory entry. This includes symlinks, even dangling
    /// ones: WebKit's check is about marker presence, not its target.
    Present,
    /// The marker lookup failed specifically with [`io::ErrorKind::NotFound`].
    Absent,
    /// The lookup could not establish presence or absence.
    Unknown(io::Error),
}

/// The environment and filesystem facts [`preflight_in`] reads.
///
/// A trait rather than closures so the real implementation and the test
/// fixtures answer exactly the same questions, and so a new question cannot be
/// added to one without the other failing to compile.
pub trait SandboxEnv {
    /// The raw value of an environment variable, if set. Not UTF-8
    /// validated: WebKit reads bytes, so a non-UTF-8 value must still be seen.
    fn var(&self, name: &str) -> Option<OsString>;
    /// Probe a marker without collapsing I/O errors into absence.
    fn marker_presence(&self, path: &str) -> MarkerPresence;
}

/// The real process environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealEnv;

impl SandboxEnv for RealEnv {
    fn var(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
    fn marker_presence(&self, path: &str) -> MarkerPresence {
        match fs::symlink_metadata(Path::new(path)) {
            Ok(_) => MarkerPresence::Present,
            Err(error) if error.kind() == io::ErrorKind::NotFound => MarkerPresence::Absent,
            Err(error) => MarkerPresence::Unknown(error),
        }
    }
}

/// Render an `OsString` for a message, reporting whether it was lossy.
fn lossy(value: &OsString) -> (String, bool) {
    match value.clone().into_string() {
        Ok(text) => (text, false),
        Err(raw) => (raw.to_string_lossy().into_owned(), true),
    }
}

/// Refuse to start a native session when the environment would weaken or skip
/// WebProcess sandboxing.
///
/// Uses the same outer-sandbox policy as the default native session
/// constructors. Flatpak applications must register their deployment before
/// this check. Each renderer still requires its own isolation proof.
///
/// # Errors
///
/// [`SandboxRefusal`], naming the exact variable or container.
pub fn preflight() -> Result<(), SandboxRefusal> {
    #[cfg(feature = "wpe")]
    let outer = crate::ffi::deployment::sandbox_policy();
    #[cfg(not(feature = "wpe"))]
    let outer = OuterSandbox::Rejected;
    preflight_in(&RealEnv, outer)
}

/// [`preflight`] against an injected environment and an explicit outer-sandbox
/// decision.
///
/// # Errors
///
/// [`SandboxRefusal`], naming the exact variable or container.
pub fn preflight_in<E: SandboxEnv + ?Sized>(
    env: &E,
    outer: OuterSandbox,
) -> Result<(), SandboxRefusal> {
    if let Some(raw) = env.var(DISABLE_VARIABLE) {
        let (value, lossy_value) = lossy(&raw);
        return Err(SandboxRefusal::DisableVariablePresent {
            value,
            lossy: lossy_value,
        });
    }
    if let Some(raw) = env.var(DEBUG_PERMISSIONS_VARIABLE) {
        return Err(SandboxRefusal::DebugPermissionsVariablePresent {
            value: lossy(&raw).0,
        });
    }
    if let Some(raw) = env.var(INSPECTOR_VARIABLE) {
        return Err(SandboxRefusal::RemoteInspectorVariablePresent {
            value: lossy(&raw).0,
        });
    }
    if let Some(raw) = env.var(INSPECTOR_HTTP_VARIABLE) {
        return Err(SandboxRefusal::RemoteInspectorHttpVariablePresent {
            value: lossy(&raw).0,
        });
    }
    if let Some(container) = detect_container(env)
        && outer == OuterSandbox::Rejected
    {
        return Err(SandboxRefusal::BubblewrapNotUsedInContainer { container });
    }
    Ok(())
}

/// Which container WebKit would decline to bubblewrap in, if any.
///
/// An indeterminate filesystem-marker probe is conservatively reported as
/// [`ContainerKind::UnverifiedContainer`]. Mirrors `WTF::isInsideFlatpak` /
/// `isInsideSnap` / `isInsideUnsupportedContainer` when probes are conclusive.
pub fn detect_container<E: SandboxEnv + ?Sized>(env: &E) -> Option<ContainerKind> {
    match env.marker_presence(FLATPAK_MARKER) {
        MarkerPresence::Present => return Some(ContainerKind::Flatpak),
        MarkerPresence::Unknown(_) => return Some(ContainerKind::UnverifiedContainer),
        MarkerPresence::Absent => {}
    }
    if SNAP_VARIABLES.iter().all(|name| env.var(name).is_some()) {
        return Some(ContainerKind::Snap);
    }
    match env.marker_presence(CONTAINER_MARKER) {
        MarkerPresence::Present | MarkerPresence::Unknown(_) => {
            Some(ContainerKind::UnverifiedContainer)
        }
        MarkerPresence::Absent => None,
    }
}

/// The kernel namespaces of one process, as the opaque inode identities
/// `/proc/<pid>/ns/*` reports (`mnt:[4026534047]`).
///
/// The strings are never parsed - only compared - so a kernel that changes the
/// format cannot make two different namespaces look equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessNamespaces {
    /// `/proc/<pid>/ns/mnt` - the filesystem view.
    pub mnt: String,
    /// `/proc/<pid>/ns/pid` - process visibility.
    pub pid: String,
    /// `/proc/<pid>/ns/user` - privilege boundary.
    pub user: String,
}

/// A process identity, not just a number.
///
/// A pid alone is not an identity: a process can exit and the kernel can reuse
/// its number between the walk that found it and the read that inspects it, so
/// a namespace comparison keyed on the pid alone can describe a completely
/// different process. `start_ticks` is `/proc/<pid>/stat` field 22, which is
/// fixed for the life of a process, so `(pid, start_ticks)` is stable and
/// re-checkable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// The process id.
    pub pid: u32,
    /// `/proc/<pid>/stat` field 22 (`starttime`), in clock ticks since boot.
    pub start_ticks: u64,
}

/// Why a namespace read did not produce a comparable answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceReadError {
    /// A `/proc/<pid>/ns/*` link could not be read.
    Unreadable {
        /// The underlying error, including the path.
        why: String,
    },
    /// The pid no longer names the process this code was asked about - it exited,
    /// and possibly a different process now holds the number.
    IdentityChanged,
}

impl ProcessNamespaces {
    /// Read the three namespaces of `identity`, re-checking identity before,
    /// after each link read, and after the complete snapshot.
    ///
    /// A vanished or reused pid returns [`NamespaceReadError::IdentityChanged`].
    /// An identity probe that is itself unreadable remains a fail-closed
    /// [`NamespaceReadError::Unreadable`] rather than being guessed vanished.
    ///
    /// # Errors
    ///
    /// [`NamespaceReadError`] when a link is unreadable or the identity moved.
    pub fn read_checked(
        identity: ProcessIdentity,
    ) -> Result<ProcessNamespaces, NamespaceReadError> {
        Self::read_checked_with(identity, read_ns, read_identity_for_namespace)
    }

    // Injected seam for deterministic identity races around namespace reads.
    fn read_checked_with(
        identity: ProcessIdentity,
        ns_reader: impl Fn(u32, &str) -> Result<String, NamespaceReadError>,
        identity_reader: impl Fn(u32) -> Result<Option<ProcessIdentity>, NamespaceReadError>,
    ) -> Result<ProcessNamespaces, NamespaceReadError> {
        require_same_identity(identity, identity_reader(identity.pid))?;
        let mnt = read_namespace_checked(identity, "mnt", &ns_reader, &identity_reader)?;
        let pid = read_namespace_checked(identity, "pid", &ns_reader, &identity_reader)?;
        let user = read_namespace_checked(identity, "user", &ns_reader, &identity_reader)?;
        require_same_identity(identity, identity_reader(identity.pid))?;
        Ok(ProcessNamespaces { mnt, pid, user })
    }

    /// Read the namespaces of a live pid whose identity is resolved here.
    ///
    /// # Errors
    ///
    /// [`NamespaceReadError`] when the pid has no `/proc` entry or a link is
    /// unreadable.
    pub fn read_current(
        pid: u32,
    ) -> Result<(ProcessIdentity, ProcessNamespaces), NamespaceReadError> {
        let identity =
            read_identity_for_namespace(pid)?.ok_or(NamespaceReadError::IdentityChanged)?;
        let namespaces = ProcessNamespaces::read_checked(identity)?;
        Ok((identity, namespaces))
    }
}

fn read_ns(pid: u32, kind: &str) -> Result<String, NamespaceReadError> {
    let path = format!("/proc/{pid}/ns/{kind}");
    fs::read_link(&path)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| NamespaceReadError::Unreadable {
            why: format!("{path}: {e}"),
        })
}

fn require_same_identity(
    expected: ProcessIdentity,
    observed: Result<Option<ProcessIdentity>, NamespaceReadError>,
) -> Result<(), NamespaceReadError> {
    match observed {
        Ok(Some(actual)) if actual == expected => Ok(()),
        Ok(_) | Err(NamespaceReadError::IdentityChanged) => {
            Err(NamespaceReadError::IdentityChanged)
        }
        Err(error @ NamespaceReadError::Unreadable { .. }) => Err(error),
    }
}

fn read_namespace_checked(
    identity: ProcessIdentity,
    kind: &str,
    ns_reader: &impl Fn(u32, &str) -> Result<String, NamespaceReadError>,
    identity_reader: &impl Fn(u32) -> Result<Option<ProcessIdentity>, NamespaceReadError>,
) -> Result<String, NamespaceReadError> {
    let namespace = ns_reader(identity.pid, kind);
    match identity_reader(identity.pid) {
        Ok(Some(actual)) if actual == identity => namespace,
        Ok(_) | Err(NamespaceReadError::IdentityChanged) => {
            Err(NamespaceReadError::IdentityChanged)
        }
        Err(identity_error @ NamespaceReadError::Unreadable { .. }) => match namespace {
            Err(namespace_error @ NamespaceReadError::Unreadable { .. }) => Err(namespace_error),
            Err(NamespaceReadError::IdentityChanged) => Err(NamespaceReadError::IdentityChanged),
            Ok(_) => Err(identity_error),
        },
    }
}

fn read_identity_for_namespace(pid: u32) -> Result<Option<ProcessIdentity>, NamespaceReadError> {
    let path = Path::new("/proc").join(pid.to_string()).join("stat");
    let stat = match fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(NamespaceReadError::Unreadable {
                why: format!("{}: {error}", path.display()),
            });
        }
    };
    let entry = parse_stat(&stat).ok_or_else(|| NamespaceReadError::Unreadable {
        why: format!("{}: malformed process stat", path.display()),
    })?;
    Ok(Some(ProcessIdentity {
        pid,
        start_ticks: entry.start_ticks,
    }))
}

/// The identity of a live pid, or `None` when it has no readable `/proc` entry.
#[must_use]
pub fn read_identity(pid: u32) -> Option<ProcessIdentity> {
    let entry = read_stat(Path::new(&format!("/proc/{pid}")))?;
    Some(ProcessIdentity {
        pid,
        start_ticks: entry.start_ticks,
    })
}

/// Which namespaces a process shares with its host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceKind {
    /// Mount namespace - the filesystem view.
    Mount,
    /// PID namespace.
    Pid,
    /// User namespace.
    User,
}

/// Every namespace `web` shares with `host`, in [`NamespaceKind`] order.
///
/// Empty means all three were unshared. A partial escape is reported in full
/// rather than rounded to "mostly sandboxed".
#[must_use]
pub fn shared_namespaces(host: &ProcessNamespaces, web: &ProcessNamespaces) -> Vec<NamespaceKind> {
    let mut shared = Vec::new();
    if host.mnt == web.mnt {
        shared.push(NamespaceKind::Mount);
    }
    if host.pid == web.pid {
        shared.push(NamespaceKind::Pid);
    }
    if host.user == web.user {
        shared.push(NamespaceKind::User);
    }
    shared
}

/// Why a renderer could not be attested as bubblewrap-isolated.
///
/// `#[non_exhaustive]`: new evidence of non-isolation must be addable without a
/// breaking change. Every variant is a refusal, so a downstream wildcard arm is
/// safe by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnattestedReason {
    /// A portal-launched renderer failed its Flatpak identity or isolation checks.
    FlatpakIsolationFailed {
        /// The native view's renderer PID, when available.
        pid: Option<u32>,
        /// The identity or kernel observation that was refused.
        why: String,
    },
    /// A process named [`BWRAP_COMM`] sits in the chain, but `/proc/<pid>/exe`
    /// is not a trusted bubblewrap binary (or could not be read).
    ///
    /// `comm` is the basename of the exec'd file, so a copy of any binary
    /// renamed `bwrap` produces the same `comm`. Without this check, an
    /// attacker-controlled launcher - or an unrelated wrapper that merely
    /// called `unshare` - would satisfy the ancestry rule.
    UntrustedBubblewrapAncestor {
        /// The renderer whose chain was inspected.
        pid: u32,
        /// The candidate launcher that failed verification.
        launcher_pid: u32,
        /// Why the executable was not trusted.
        why: String,
    },
    /// The renderer shares these namespaces with the host process.
    SharesHostNamespaces {
        /// The renderer pid inspected.
        pid: u32,
        /// Every namespace found identical to the host's.
        shared: Vec<NamespaceKind>,
    },
    /// The renderer's namespaces are unshared, but no [`BWRAP_COMM`] process
    /// sits between it and this code.
    ///
    /// Unshared namespaces alone say only "somebody called `unshare`". Without
    /// WebKit's own launcher in the chain there is no reason to believe the
    /// mount policy, the seccomp filter or the D-Bus proxy were applied, and a
    /// verdict that ignored ancestry would accept a renderer isolated by
    /// something else entirely.
    NoBubblewrapAncestor {
        /// The renderer pid inspected.
        pid: u32,
        /// The `comm` chain from the renderer up to this process.
        chain: Vec<String>,
    },
    /// A namespace link could not be read, so isolation is unknown.
    NamespacesUnreadable {
        /// The process that could not be inspected.
        pid: u32,
        /// The underlying error.
        why: String,
    },
    /// The renderer exited between discovery and inspection, so its pid may
    /// now belong to a different process.
    ProcessVanished {
        /// The pid whose identity moved.
        pid: u32,
    },
    /// No [`WEB_PROCESS_COMM`] descendant exists.
    ///
    /// Not an error: before the first page load there is genuinely no
    /// WebProcess. It is still not an attestation.
    WebProcessNotFound,
}

/// The result of attesting the WebProcesses this process spawned.
///
/// `#[non_exhaustive]`: see [`UnattestedReason`]. Downstream code must treat any
/// variant it does not recognise as *not* attested, which a wildcard arm does.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SandboxAttestation {
    /// A native-view-identified renderer matches an installed helper and a separate
    /// Flatpak sandbox for this application's exact app and runtime commits.
    /// Mount, PID and network namespaces differ; seccomp and no-new-privileges
    /// are enabled. Flatpak may share its user namespace between these sandboxes.
    FlatpakIsolated {
        /// The identity checked before and after the observations.
        renderer: ProcessIdentity,
        /// The application's namespace identifiers.
        host: ProcessNamespaces,
        /// The renderer's namespace identifiers.
        web: ProcessNamespaces,
        /// The matching Flatpak application ID.
        application_id: String,
    },
    /// The renderer was reached through a `bwrap` ancestor and differs
    /// from this process in the mount, PID and user namespaces.
    ///
    /// # What this does not claim
    ///
    /// It does not claim the sandbox is tight. It does not inspect the
    /// mount policy (a `bwrap --ro-bind / /` child satisfies every condition
    /// here and can still read the whole filesystem read-only), the seccomp
    /// filter, `no_new_privs`, the network namespace, or the D-Bus proxy. It
    /// is the strongest claim that is *observable from outside the sandbox*:
    /// WebKit's launcher ran, and the kernel gave the renderer its own mount,
    /// PID and user namespaces. Anything stronger needs cooperation from
    /// inside the renderer, which this process does not have.
    BubblewrapIsolated {
        /// The renderer, as a re-checkable identity.
        renderer: ProcessIdentity,
        /// The closest `bwrap` ancestor between the renderer and this code.
        bwrap_ancestor: ProcessIdentity,
        /// This process's namespaces, for the record.
        host: ProcessNamespaces,
        /// The renderer's namespaces, for the record.
        web: ProcessNamespaces,
    },
    /// Not attested, for a stated reason.
    Unattested(UnattestedReason),
}

impl SandboxAttestation {
    /// Whether the renderer has an observed bubblewrap or Flatpak isolation proof.
    #[must_use]
    pub fn is_isolated(&self) -> bool {
        matches!(
            self,
            SandboxAttestation::BubblewrapIsolated { .. }
                | SandboxAttestation::FlatpakIsolated { .. }
        )
    }

    /// The renderer this verdict is about, when it names one.
    ///
    /// The caller that must *act* on a refusal needs to know which process to
    /// stop; a verdict that names no process (nothing found, host unreadable)
    /// gives `None`, and the caller must then refuse rather than kill something
    /// arbitrary.
    #[must_use]
    pub fn subject(&self) -> Option<ProcessIdentity> {
        match self {
            SandboxAttestation::BubblewrapIsolated { renderer, .. }
            | SandboxAttestation::FlatpakIsolated { renderer, .. } => Some(*renderer),
            SandboxAttestation::Unattested(reason) => reason.subject_pid().and_then(read_identity),
        }
    }

    /// A short line for a status surface. Never says "confined".
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            SandboxAttestation::FlatpakIsolated {
                renderer,
                application_id,
                ..
            } => format!(
                "WebProcess {} isolated by Flatpak for {} (mnt/pid/net unshared; seccomp and no-new-privileges enabled)",
                renderer.pid, application_id
            ),
            SandboxAttestation::Unattested(UnattestedReason::FlatpakIsolationFailed {
                pid,
                why,
            }) => format!("Flatpak WebProcess {pid:?} unverifiable: {why}"),
            SandboxAttestation::BubblewrapIsolated {
                renderer,
                bwrap_ancestor,
                ..
            } => format!(
                "WebProcess {} isolated via bwrap {} (mnt/pid/user unshared; \
                 mount policy and seccomp not inspected)",
                renderer.pid, bwrap_ancestor.pid
            ),
            SandboxAttestation::Unattested(UnattestedReason::SharesHostNamespaces {
                pid,
                shared,
            }) => format!("WebProcess {pid} NOT ISOLATED: shares {shared:?} with host"),
            SandboxAttestation::Unattested(UnattestedReason::NoBubblewrapAncestor {
                pid,
                chain,
            }) => format!("WebProcess {pid} NOT ISOLATED: no bwrap ancestor (chain {chain:?})"),
            SandboxAttestation::Unattested(UnattestedReason::UntrustedBubblewrapAncestor {
                pid,
                launcher_pid,
                why,
            }) => format!(
                "WebProcess {pid} NOT ISOLATED: ancestor {launcher_pid} is named bwrap but \
                 is not a trusted bwrap binary ({why})"
            ),
            SandboxAttestation::Unattested(UnattestedReason::NamespacesUnreadable { pid, why }) => {
                format!("WebProcess {pid} unverifiable: {why}")
            }
            SandboxAttestation::Unattested(UnattestedReason::ProcessVanished { pid }) => {
                format!("WebProcess {pid} vanished during inspection; verdict withheld")
            }
            SandboxAttestation::Unattested(UnattestedReason::WebProcessNotFound) => {
                "no WebProcess spawned yet".to_string()
            }
        }
    }
}

impl UnattestedReason {
    /// The renderer pid this reason is about, when it names one.
    #[must_use]
    pub fn subject_pid(&self) -> Option<u32> {
        match self {
            UnattestedReason::FlatpakIsolationFailed { pid, .. } => *pid,
            UnattestedReason::SharesHostNamespaces { pid, .. }
            | UnattestedReason::NoBubblewrapAncestor { pid, .. }
            | UnattestedReason::UntrustedBubblewrapAncestor { pid, .. }
            | UnattestedReason::NamespacesUnreadable { pid, .. }
            | UnattestedReason::ProcessVanished { pid } => Some(*pid),
            UnattestedReason::WebProcessNotFound => None,
        }
    }
}

/// One `/proc/<pid>/stat` row.
#[derive(Debug, Clone)]
struct ProcEntry {
    ppid: u32,
    comm: String,
    start_ticks: u64,
    /// The `/proc/PID/stat` state letter (field 3).
    state: char,
}

impl ProcEntry {
    /// A zombie (`Z`) or dead (`X`) process has exited: it runs nothing and
    /// has no children, and only waits for its parent to reap it. A renderer
    /// whose sandbox parent has not reaped it yet is gone for every question
    /// asked here.
    fn has_exited(&self) -> bool {
        matches!(self.state, 'Z' | 'X' | 'x')
    }
}

/// A snapshot of `/proc`: pid -> (ppid, comm, start time).
///
/// Taken once so a walk cannot see a half-changed tree; the start times make
/// every pid it hands out re-checkable afterwards.
#[derive(Debug, Clone, Default)]
pub struct ProcessTable {
    entries: HashMap<u32, ProcEntry>,
}

impl ProcessTable {
    /// Read every readable `/proc/<pid>/stat`.
    ///
    /// Processes that vanish mid-scan are skipped, not fatal.
    #[must_use]
    pub fn read() -> ProcessTable {
        let mut entries = HashMap::new();
        let Ok(dir) = fs::read_dir("/proc") else {
            return ProcessTable { entries };
        };
        for entry in dir.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let Some(parsed) = read_stat(&entry.path()) else {
                continue;
            };
            entries.insert(pid, parsed);
        }
        ProcessTable { entries }
    }

    /// Build a table directly, for tests of the walk itself.
    ///
    /// Entries are `(pid, ppid, comm, start_ticks)`.
    #[must_use]
    pub fn from_entries(
        entries: impl IntoIterator<Item = (u32, u32, String, u64)>,
    ) -> ProcessTable {
        ProcessTable {
            entries: entries
                .into_iter()
                .map(|(pid, ppid, comm, start_ticks)| {
                    (
                        pid,
                        ProcEntry {
                            ppid,
                            comm,
                            start_ticks,
                            state: 'S',
                        },
                    )
                })
                .collect(),
        }
    }

    /// How many processes the snapshot covers - the floor a caller can assert
    /// so an empty `/proc` read cannot pass as "nothing suspicious found".
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the snapshot saw nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `/proc/<pid>/comm` for `pid`.
    #[must_use]
    pub fn comm(&self, pid: u32) -> Option<&str> {
        self.entries.get(&pid).map(|e| e.comm.as_str())
    }

    /// The parent pid recorded for `pid`.
    #[must_use]
    pub fn ppid(&self, pid: u32) -> Option<u32> {
        self.entries.get(&pid).map(|e| e.ppid)
    }

    /// The re-checkable identity recorded for `pid`.
    #[must_use]
    pub fn identity(&self, pid: u32) -> Option<ProcessIdentity> {
        self.entries.get(&pid).map(|e| ProcessIdentity {
            pid,
            start_ticks: e.start_ticks,
        })
    }

    /// Every transitive descendant of `root`, breadth first.
    ///
    /// Cycle-safe: a pid is expanded at most once, so a corrupted table cannot
    /// spin. `root` itself is not included.
    #[must_use]
    pub fn descendants(&self, root: u32) -> Vec<u32> {
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for (&pid, entry) in &self.entries {
            children.entry(entry.ppid).or_default().push(pid);
        }
        let mut seen = vec![root];
        let mut queue = vec![root];
        let mut out = Vec::new();
        while let Some(cur) = queue.pop() {
            let Some(kids) = children.get(&cur) else {
                continue;
            };
            for &kid in kids {
                if seen.contains(&kid) {
                    continue;
                }
                seen.push(kid);
                out.push(kid);
                queue.push(kid);
            }
        }
        out.sort_unstable();
        out
    }

    /// The chain of pids from `pid`'s parent up to (and excluding) `root`.
    ///
    /// `None` when the walk does not reach `root` - the process is not this one's descendant,
    /// so no ancestry claim can be made about it. Bounded by the table size,
    /// so a cyclic `ppid` cannot spin.
    #[must_use]
    pub fn ancestry_to(&self, pid: u32, root: u32) -> Option<Vec<u32>> {
        let mut chain = Vec::new();
        let mut cur = pid;
        for _ in 0..=self.entries.len() {
            let parent = self.ppid(cur)?;
            if parent == root {
                return Some(chain);
            }
            if chain.contains(&parent) || parent == 0 {
                return None;
            }
            chain.push(parent);
            cur = parent;
        }
        None
    }

    /// The closest [`BWRAP_COMM`] ancestor of `pid` below `root`, if any.
    #[must_use]
    pub fn bwrap_ancestor(&self, pid: u32, root: u32) -> Option<ProcessIdentity> {
        let chain = self.ancestry_to(pid, root)?;
        chain
            .into_iter()
            .find(|p| self.comm(*p) == Some(BWRAP_COMM))
            .and_then(|p| self.identity(p))
    }

    /// The `comm` chain from `pid` up to `root`, for a legible refusal.
    #[must_use]
    pub fn comm_chain_to(&self, pid: u32, root: u32) -> Vec<String> {
        let mut chain = vec![self.comm(pid).unwrap_or("<gone>").to_string()];
        if let Some(ancestors) = self.ancestry_to(pid, root) {
            for parent in ancestors {
                chain.push(self.comm(parent).unwrap_or("<gone>").to_string());
            }
        }
        chain
    }

    /// Every [`WEB_PROCESS_COMM`] descendant of `root`, as identities.
    #[must_use]
    pub fn web_processes(&self, root: u32) -> Vec<ProcessIdentity> {
        self.processes_named(root, WEB_PROCESS_COMM)
    }

    /// Every [`GPU_PROCESS_COMM`] descendant of `root`, as identities.
    #[must_use]
    pub fn gpu_processes(&self, root: u32) -> Vec<ProcessIdentity> {
        self.processes_named(root, GPU_PROCESS_COMM)
    }

    fn processes_named(&self, root: u32, comm: &str) -> Vec<ProcessIdentity> {
        self.descendants(root)
            .into_iter()
            .filter(|pid| self.comm(*pid) == Some(comm))
            .filter_map(|pid| self.identity(pid))
            .collect()
    }
}

fn read_stat(dir: &Path) -> Option<ProcEntry> {
    let stat = fs::read_to_string(dir.join("stat")).ok()?;
    parse_stat(&stat).filter(|entry| !entry.has_exited())
}

fn parse_stat(stat: &str) -> Option<ProcEntry> {
    // The kernel's comm field may itself contain closing parentheses.
    let close = stat.rfind(')')?;
    let open = stat.find('(')?;
    let comm = stat.get(open + 1..close)?.to_string();
    let mut tail = stat.get(close + 2..)?.split_whitespace();
    let state = tail.next()?.chars().next()?;
    let ppid = tail.next()?.parse::<u32>().ok()?;
    // starttime is field 22, after the consumed state and ppid fields.
    let start_ticks = tail.nth(17)?.parse::<u64>().ok()?;
    Some(ProcEntry {
        ppid,
        comm,
        start_ticks,
        state,
    })
}

/// Attest every WebProcess spawned by `root_pid`, against `root_pid`'s own
/// namespaces.
///
/// With more than one WebProcess the verdict is the worst one: a single
/// non-isolated renderer is the whole answer. A GPU process, when one exists,
/// must be isolated too.
#[must_use]
pub fn attest_tree(table: &ProcessTable, root_pid: u32) -> SandboxAttestation {
    attest_tree_excluding(table, root_pid, &[])
}

/// [`attest_tree`], ignoring renderers whose identity is in `exclude`.
///
/// A `WebSession` uses this to scope the verdict to the renderers that appeared
/// after it constructed its own view, instead of taking the worst renderer
/// in the whole process. Killing a view's WebProcess because a *different*
/// view's renderer is unconfined would both spare the offender and punish the
/// innocent; excluding the pre-existing set is the closest scoping available
/// from outside WebKit, which exposes no pid for a `WebKitWebView`.
///
/// The exclusion is by `(pid, start_ticks)` identity, so a recycled pid is not
/// silently excluded.
#[must_use]
pub fn attest_tree_excluding(
    table: &ProcessTable,
    root_pid: u32,
    exclude: &[ProcessIdentity],
) -> SandboxAttestation {
    let host = match ProcessNamespaces::read_current(root_pid) {
        Ok((_, host)) => host,
        Err(NamespaceReadError::Unreadable { why }) => {
            return SandboxAttestation::Unattested(UnattestedReason::NamespacesUnreadable {
                pid: root_pid,
                why,
            });
        }
        Err(NamespaceReadError::IdentityChanged) => {
            return SandboxAttestation::Unattested(UnattestedReason::NamespacesUnreadable {
                pid: root_pid,
                why: format!("/proc/{root_pid}/stat: unreadable host process"),
            });
        }
    };
    let mut best: Option<SandboxAttestation> = None;
    for renderer in table.web_processes(root_pid) {
        if exclude.contains(&renderer) {
            continue;
        }
        let verdict = attest_one(table, root_pid, renderer, &host);
        if !verdict.is_isolated() {
            return verdict;
        }
        best.get_or_insert(verdict);
    }
    for gpu in table.gpu_processes(root_pid) {
        let verdict = attest_one(table, root_pid, gpu, &host);
        if !verdict.is_isolated() {
            return verdict;
        }
    }
    best.unwrap_or(SandboxAttestation::Unattested(
        UnattestedReason::WebProcessNotFound,
    ))
}

fn attest_one(
    table: &ProcessTable,
    root_pid: u32,
    renderer: ProcessIdentity,
    host: &ProcessNamespaces,
) -> SandboxAttestation {
    let web = match ProcessNamespaces::read_checked(renderer) {
        Ok(web) => web,
        Err(NamespaceReadError::Unreadable { why }) => {
            return SandboxAttestation::Unattested(UnattestedReason::NamespacesUnreadable {
                pid: renderer.pid,
                why,
            });
        }
        Err(NamespaceReadError::IdentityChanged) => {
            return SandboxAttestation::Unattested(UnattestedReason::ProcessVanished {
                pid: renderer.pid,
            });
        }
    };
    let shared = shared_namespaces(host, &web);
    if !shared.is_empty() {
        return SandboxAttestation::Unattested(UnattestedReason::SharesHostNamespaces {
            pid: renderer.pid,
            shared,
        });
    }
    let Some(bwrap_ancestor) = table.bwrap_ancestor(renderer.pid, root_pid) else {
        return SandboxAttestation::Unattested(UnattestedReason::NoBubblewrapAncestor {
            pid: renderer.pid,
            chain: table.comm_chain_to(renderer.pid, root_pid),
        });
    };
    // The ancestor must still be the same process this code walked, or the asserted
    // chain no longer exists.
    if read_identity(bwrap_ancestor.pid) != Some(bwrap_ancestor) {
        return SandboxAttestation::Unattested(UnattestedReason::ProcessVanished {
            pid: bwrap_ancestor.pid,
        });
    }
    // ...and it must actually BE bubblewrap. `comm` is the basename of the
    // exec'd file and is attacker-choosable; `/proc/<pid>/exe` is the kernel's
    // own answer, compared by device+inode against the installed binary.
    if let Err(why) = verify_launcher_executable(bwrap_ancestor.pid) {
        return SandboxAttestation::Unattested(UnattestedReason::UntrustedBubblewrapAncestor {
            pid: renderer.pid,
            launcher_pid: bwrap_ancestor.pid,
            why,
        });
    }
    // Re-check identity after the exe read: if the launcher exited during
    // verification, the file this code stat'd may belong to its replacement.
    if read_identity(bwrap_ancestor.pid) != Some(bwrap_ancestor) {
        return SandboxAttestation::Unattested(UnattestedReason::ProcessVanished {
            pid: bwrap_ancestor.pid,
        });
    }
    SandboxAttestation::BubblewrapIsolated {
        renderer,
        bwrap_ancestor,
        host: host.clone(),
        web,
    }
}

/// Attest the WebProcesses this process has spawned.
///
/// Reads `/proc`, so it is blocking I/O: call it from a bounded worker or
/// an explicit action, never from a per-frame view build.
#[must_use]
pub fn attest_current_process() -> SandboxAttestation {
    attest_tree(&ProcessTable::read(), std::process::id())
}

/// [`attest_current_process`], scoped to renderers not in `exclude`.
#[must_use]
pub fn attest_current_process_excluding(exclude: &[ProcessIdentity]) -> SandboxAttestation {
    attest_tree_excluding(&ProcessTable::read(), std::process::id(), exclude)
}

/// Every WebProcess identity this process currently owns - the baseline a
/// session records before it constructs its own view.
#[must_use]
pub fn current_web_processes() -> Vec<ProcessIdentity> {
    ProcessTable::read().web_processes(std::process::id())
}

/// `true` when the exact process `identity` no longer exists.
///
/// Identity, not pid: a reused pid is "gone" for the process this code meants.
#[must_use]
pub fn process_is_gone(identity: ProcessIdentity) -> bool {
    read_identity(identity.pid) != Some(identity)
}

/// The container this process is in right now, per WebKit's own rules.
#[must_use]
pub fn detect_container_now() -> Option<ContainerKind> {
    detect_container(&RealEnv)
}

/// The enforcement decision, separated from the side effect that carries it
/// out.
///
/// `WebSession` terminates the renderer and fails the load on `Err`. Killing a
/// WebProcess cannot be exercised without an unsandboxed host, so the *policy*
/// lives here where it can be: every non-attestation is a refusal, and only
/// [`SandboxAttestation::BubblewrapIsolated`] is allowed to continue. A
/// mapping that let any `Unattested` reason through would be the fail-open.
///
/// # Errors
///
/// The [`UnattestedReason`] the caller must report and act on.
pub fn enforcement_decision(verdict: &SandboxAttestation) -> Result<(), UnattestedReason> {
    enforcement_decision_with_outer(verdict, OuterSandbox::Rejected, None)
}

/// The enforcement decision under an explicit outer-sandbox policy.
///
/// Flatpak requires a positive [`SandboxAttestation::FlatpakIsolated`] proof
/// for the native view's renderer and explicit host acceptance. Missing inner
/// isolation is refused even when an outer Flatpak sandbox is present.
///
/// Other detected containers retain their explicit outer-policy handling for
/// shared namespaces or a missing bubblewrap ancestor. Unreadable metadata,
/// vanished renderers and untrusted launchers remain refusals. Acceptance on a
/// non-container host does not relax renderer attestation.
///
/// # Errors
///
/// The [`UnattestedReason`] the caller must report and act on.
pub fn enforcement_decision_with_outer(
    verdict: &SandboxAttestation,
    outer: OuterSandbox,
    container: Option<ContainerKind>,
) -> Result<(), UnattestedReason> {
    match verdict {
        SandboxAttestation::BubblewrapIsolated { .. } => Ok(()),
        SandboxAttestation::FlatpakIsolated { renderer, .. } => {
            if outer == OuterSandbox::AcceptedByHost && container == Some(ContainerKind::Flatpak) {
                Ok(())
            } else {
                Err(UnattestedReason::FlatpakIsolationFailed {
                    pid: Some(renderer.pid),
                    why: "Flatpak renderer proof requires an explicitly accepted Flatpak host"
                        .into(),
                })
            }
        }
        SandboxAttestation::Unattested(reason) => {
            let explained_by_outer = matches!(
                reason,
                UnattestedReason::SharesHostNamespaces { .. }
                    | UnattestedReason::NoBubblewrapAncestor { .. }
            );
            if outer == OuterSandbox::AcceptedByHost
                && container.is_some()
                && container != Some(ContainerKind::Flatpak)
                && explained_by_outer
            {
                Ok(())
            } else {
                Err(reason.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests;
