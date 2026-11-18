//! Symlink-safe, user-private provisioning of persistent profile directories.
//!
//! Directories are created with mode 0700, tightened through a held descriptor
//! when only too permissive, and refused when foreign-owned, symlinked or not
//! directories. [`begin_persistent_profile_tree`] returns a guard that rolls back
//! only the directories its attempt created, matched by held inode identity.
//!

use std::path::{Path, PathBuf};

/// The user-private mode this module enforces on every profile directory it
/// touches (0700 - owner rwx only).
pub const PROFILE_DIR_MODE: u32 = 0o700;

/// A refusal from [`provision_persistent_profile_tree`] or
/// [`secure_ensure_dir`]. Every variant names the exact directory and, where
/// it applies, the observed uid/mode - so a caller can log which component
/// tripped the guard and why.
///
/// # Compatibility
///
/// `#[non_exhaustive]`: this enum grows whenever a new refusal is discovered
/// (including `RollbackSubstituted`), and every caller in the
/// workspace formats it rather than matching it exhaustively
/// (`ffi::profile::ProfileStore` maps it to `ProfileError::ProfileFs` via
/// `to_string`). Marking it non-exhaustive makes the next variant a
/// non-breaking change instead of a silent semver break in a `publish = false`
/// crate that nobody would have caught.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProvisionError {
    /// A component along the profile path is a symlink. Never followed.
    SymlinkedComponent(PathBuf),
    /// A component exists but is not a directory (file, FIFO, socket, device,
    /// …). Refused so the network session cannot open cookies against it.
    NonDirectory(PathBuf),
    /// Rollback refused to delete at least one recorded pathname because the
    /// inode living there is no longer the one this transaction created.
    ///
    /// This is the TOCTOU-substitution refusal: between creation and the
    /// post-backend cleanup the pathname was rebound to a different inode
    /// (recreated directory, symlink, file). Deleting it would destroy data
    /// this transaction never owned, so nothing is deleted at that path - or
    /// at any ancestor of it.
    RollbackSubstituted {
        /// The original failure that triggered rollback.
        cause: String,
        /// Recorded paths whose inode identity no longer matches.
        substituted: Vec<PathBuf>,
        /// Ancestors left in place because a substituted path lives under
        /// them; removing them would have deleted the replacement.
        retained: Vec<PathBuf>,
        /// Directories this transaction *did* create whose removal failed
        /// anyway. Carried here so a substitution refusal never swallows the
        /// [`ProvisionError::RollbackFailed`] half of the same rollback.
        leftovers: Vec<PathBuf>,
    },
    /// A component exists and is a directory, but is owned by a different uid.
    /// Refused: adopting a directory another uid owns would let them read or
    /// redirect the cookies.
    ForeignOwner {
        /// The offending directory.
        path: PathBuf,
        /// The uid the kernel reports as the directory's owner.
        dir_uid: u32,
        /// This process's effective uid, as observed by [`current_uid`].
        our_uid: u32,
    },
    /// This code could not determine its own uid, so this code cannot compare it to any
    /// directory's owner. Fail-closed refusal; never treated as "check passed".
    OwnerUnverifiable,
    /// A directory exists and is owned by the current user, but chmodding it to 0700 failed. The
    /// only way to reach this is a filesystem that returns `EPERM`/`EROFS` for
    /// a chmod this code should be allowed to do; treated as a refusal because a
    /// still-permissive profile directory is exactly the exposure this code exists to
    /// prevent.
    ChmodFailed {
        /// The directory this code was trying to tighten.
        path: PathBuf,
        /// The observed mode (permission bits only).
        mode: u32,
        /// The underlying I/O error as a string (`io::Error` is not `Clone`).
        error: String,
    },
    /// A fault injected after a successful provisioning step.
    ///
    /// Production never constructs this variant. It exists so the transaction's
    /// first, middle, and last rollback paths can be exercised without relying
    /// on host-specific permission or disk-full failures.
    FaultInjected {
        /// The directory that had just been secured when the fault fired.
        path: PathBuf,
        /// Diagnostic supplied by the injector.
        label: String,
    },
    /// Provisioning failed and at least one directory created by this attempt
    /// could not be removed during rollback.
    ///
    /// Existing directories and their contents are never rollback candidates.
    RollbackFailed {
        /// The original provisioning failure.
        cause: String,
        /// Newly-created directories that still exist after reverse cleanup.
        leftovers: Vec<PathBuf>,
    },
    /// A generic I/O failure (e.g. `EACCES` walking a parent). Kept typed so
    /// callers see a `ProvisionError`, not a stringly-typed catch-all.
    Io {
        /// The path being touched when the error occurred.
        path: PathBuf,
        /// The underlying I/O error as a string.
        error: String,
    },
}

impl core::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SymlinkedComponent(p) => write!(
                f,
                "profile path component is a symlink and was refused: {}",
                p.display()
            ),
            Self::NonDirectory(p) => write!(
                f,
                "profile path component exists but is not a directory: {}",
                p.display()
            ),
            Self::ForeignOwner {
                path,
                dir_uid,
                our_uid,
            } => write!(
                f,
                "profile directory {} is owned by uid {dir_uid}, not our uid {our_uid}",
                path.display()
            ),
            Self::OwnerUnverifiable => write!(
                f,
                "could not determine our own uid, so profile ownership cannot be verified"
            ),
            Self::ChmodFailed { path, mode, error } => write!(
                f,
                "could not tighten profile directory {} from mode {mode:04o} to 0700: {error}",
                path.display()
            ),
            Self::FaultInjected { path, label } => write!(
                f,
                "profile provisioning fault after {}: {label}",
                path.display()
            ),
            Self::RollbackSubstituted {
                cause,
                substituted,
                retained,
                leftovers,
            } => write!(
                f,
                "profile provisioning failed ({cause}) and rollback refused {} substituted \
                 path(s) whose inode no longer matches the one created: {}; retained {} \
                 ancestor(s): {}; left {} created director(y/ies): {}",
                substituted.len(),
                join_paths(substituted),
                retained.len(),
                join_paths(retained),
                leftovers.len(),
                join_paths(leftovers)
            ),
            Self::RollbackFailed { cause, leftovers } => write!(
                f,
                "profile provisioning failed ({cause}) and rollback left {} director{}: {}",
                leftovers.len(),
                if leftovers.len() == 1 { "y" } else { "ies" },
                leftovers
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Io { path, error } => write!(
                f,
                "profile directory I/O error at {}: {error}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ProvisionError {}

fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The kernel identity of a directory this transaction created: the pair that
/// distinguishes an inode from any replacement that later takes its pathname.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirIdentity {
    dev: u64,
    ino: u64,
}

impl DirIdentity {
    fn of(md: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: md.dev(),
            ino: md.ino(),
        }
    }

    /// Observe the identity of `path` without following a final symlink.
    ///
    /// `symlink_metadata` is load-bearing: a symlink swapped in for the created
    /// directory reports the *link's* identity here, which cannot match the
    /// directory this code holds open, so the swap is refused rather than followed.
    fn observe(path: &Path) -> std::io::Result<Self> {
        Ok(Self::of(&std::fs::symlink_metadata(path)?))
    }
}

/// One directory this transaction created, bound to the inode it created - not
/// merely to the pathname, which a racing process can rebind while the caller
/// blocks in backend construction.
///
/// `fd` is the binding. It is kept open from creation until the transaction
/// commits or rolls back, which pins the inode: a freed inode number can be
/// handed to the next `mkdir`, a held one cannot.
#[derive(Debug)]
struct CreatedDir {
    path: PathBuf,
    fd: std::fs::File,
}

impl CreatedDir {
    /// The identity of the inode this code holds, read from the descriptor (`fstat`),
    /// never from the pathname.
    fn pinned_identity(&self) -> std::io::Result<DirIdentity> {
        Ok(DirIdentity::of(&self.fd.metadata()?))
    }
}

/// Remove `path` only if it still resolves to `identity`.
///
/// Every cleanup in this module goes through here, including the cleanup of a
/// directory whose own post-create validation failed. Two properties make it
/// safe, and both are load-bearing:
///
/// * directory-only - `remove_dir_all` refuses a regular file (`ENOTDIR`)
///   and refuses a symlink rather than following it, so a non-directory
///   substituted at the pathname is never unlinked, even though it may have
///   been opened (`open(2)` follows the pathname, so a substituted file's own
///   identity is what is held, and identity alone cannot reject it; the type
///   check does).
///   Sabotage: add `let _ = std::fs::remove_file(path);` here and
///   `creation_refusal_cleanup_spares_a_substituted_entry` reddens.
/// * identity-bound - a *directory* is removed only while the pathname
///   resolves to the inode held open at the final observation.
///   Sabotage: drop the comparison and
///   `rollback_refuses_a_directory_recreated_at_a_recorded_path` reddens
///   through the shared removal path.
///
/// POSIX has no remove-directory-by-inode operation. A same-uid actor can still
/// rebind the name between the final `lstat` and `remove_dir_all`; this check
/// strictly narrows that race but is not an atomic unlink guarantee.
fn remove_if_identity_matches(path: &Path, identity: DirIdentity) {
    if matches!(DirIdentity::observe(path), Ok(seen) if seen == identity) {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// The provisioned profile subtree: the two directories WebKit is handed for
/// its network session (`data` holds `cookies.sqlite` and localStorage; `cache`
/// holds the HTTP cache).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePaths {
    /// The data directory, at `<root>/<relative>/data`.
    pub data: PathBuf,
    /// The cache directory, at `<root>/<relative>/cache`.
    pub cache: PathBuf,
}

/// Uncommitted profile-tree provisioning.
///
/// The production WebKit consumer keeps this guard alive while constructing
/// the backend session. It calls [`commit`](Self::commit) only after WebKit has
/// accepted both paths; any earlier error calls [`rollback`](Self::rollback),
/// preventing a failed backend construction from leaving a plausible empty
/// profile behind.
#[derive(Debug)]
pub struct ProfileProvision {
    paths: ProfilePaths,
    created: Vec<CreatedDir>,
    /// Directories that already existed and were adopted. Never removed, and
    /// never swept *through*: a directory this transaction
    /// created can contain one of these when a racing instance published a
    /// child first, and `remove_dir_all` on the ancestor would take the
    /// adopted child's data with it.
    adopted: Vec<PathBuf>,
}

impl ProfileProvision {
    /// Paths to pass to the backend while this provision remains uncommitted.
    #[must_use]
    pub const fn paths(&self) -> &ProfilePaths {
        &self.paths
    }

    /// Commit the provision after the backend accepted the paths.
    #[must_use]
    pub fn commit(mut self) -> ProfilePaths {
        self.created.clear();
        self.paths.clone()
    }

    /// Roll back every directory created by this attempt, deepest first.
    /// Existing directories and their contents are never removed.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::RollbackFailed`] if a newly-created subtree could not
    /// be removed. Backend-created files inside that subtree are rollback-owned
    /// and are removed with it; pre-existing directories are never candidates.
    ///
    /// [`ProvisionError::RollbackSubstituted`] if a recorded pathname now holds
    /// a different inode than the one created - nothing is deleted there, and
    /// any leftover of the same rollback is reported alongside it.
    pub fn rollback(mut self) -> Result<(), ProvisionError> {
        rollback_paths(
            std::mem::take(&mut self.created),
            &self.adopted,
            "downstream profile backend refused the paths",
        )
    }
}

impl Drop for ProfileProvision {
    fn drop(&mut self) {
        // Fail-safe for a caller that returns early without choosing explicitly.
        // Explicit `rollback` is still preferred because it can surface a rare
        // cleanup failure instead of discarding it from `Drop`.
        let _ = rollback_paths(
            std::mem::take(&mut self.created),
            &self.adopted,
            "uncommitted profile provision was dropped",
        );
    }
}

/// Fail-closed, symlink-safe provision of `<root>/<relative>/{data,cache}`
/// for a persistent profile.
///
/// Every component from `root` (inclusive) down to `data` and `cache` is passed
/// through [`secure_ensure_dir`], so the whole subtree is a chain of
/// user-owned, mode-0700, real (not symlinked) directories by the time this
/// returns. See the module docs for the five ownership/type/mode decisions and
/// which gate proves each.
///
/// # Errors
///
/// Any [`ProvisionError`] variant surfaces the failed component and reason.
pub fn provision_persistent_profile_tree(
    root: &Path,
    relative: &Path,
) -> Result<ProfilePaths, ProvisionError> {
    provision_persistent_profile_tree_with_uid(root, relative, current_uid())
}

/// Test seam: [`provision_persistent_profile_tree`] with the "the uid" observation
/// injected. Production always uses [`current_uid`]; a gate injects a wrong uid
/// to reach [`ProvisionError::ForeignOwner`] without holding a real cross-uid
/// directory (which a single-user test run cannot create).
///
/// # Errors
///
/// As [`provision_persistent_profile_tree`].
#[doc(hidden)]
pub fn provision_persistent_profile_tree_with_uid(
    root: &Path,
    relative: &Path,
    our_uid: Option<u32>,
) -> Result<ProfilePaths, ProvisionError> {
    begin_persistent_profile_tree_with_uid_and_gate(root, relative, our_uid, |_| Ok(()))
        .map(ProfileProvision::commit)
}

/// The `(dev, ino)` pairs pinned by the descriptors this transaction holds.
///
/// Test seam for `held_descriptor_pins_the_created_inode_number`: production
/// code never needs the numbers, only the comparison rollback makes.
#[doc(hidden)]
#[must_use]
pub fn pinned_identities(provision: &ProfileProvision) -> Vec<(u64, u64)> {
    provision
        .created
        .iter()
        .filter_map(|dir| dir.pinned_identity().ok())
        .map(|id| (id.dev, id.ino))
        .collect()
}

/// Begin provisioning without committing the newly-created directories.
///
/// A caller that has another fallible construction step must keep the returned
/// guard until that step succeeds, then call [`ProfileProvision::commit`]. On
/// failure it calls [`ProfileProvision::rollback`] before reporting the error.
///
/// # Errors
///
/// As [`provision_persistent_profile_tree`].
pub fn begin_persistent_profile_tree(
    root: &Path,
    relative: &Path,
) -> Result<ProfileProvision, ProvisionError> {
    begin_persistent_profile_tree_with_uid_and_gate(root, relative, current_uid(), |_| Ok(()))
}

/// Transactional test seam for [`provision_persistent_profile_tree`].
///
/// `gate` runs after each directory has been secured. Returning `Err(label)`
/// simulates the next fallible subsystem rejecting the partially provisioned
/// tree. Every directory created by this call is then removed in reverse order;
/// directories that existed before the call are never removed. Production uses
/// the same path with a gate that always succeeds.
///
/// Tightening an existing owned directory from a permissive mode to `0700` is
/// intentionally monotonic and is not undone: rollback must never re-expose
/// cookies merely to recreate an insecure pre-call state.
#[doc(hidden)]
pub fn begin_persistent_profile_tree_with_uid_and_gate(
    root: &Path,
    relative: &Path,
    our_uid: Option<u32>,
    gate: impl FnMut(ProvisionCheckpoint<'_>) -> Result<(), String>,
) -> Result<ProfileProvision, ProvisionError> {
    begin_persistent_profile_tree_inner(root, relative, our_uid, gate, |_, _| {}, |_, _| {})
}

/// Where in the creation of one directory a [`begin_persistent_profile_tree_with_creation_seam`]
/// hook fires.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreationPhase {
    /// Immediately before `mkdir(2)` at the final pathname. A gate publishes a
    /// racing winner here to exercise the no-clobber `EEXIST` arm.
    BeforeCreate,
    /// After `mkdir(2)` succeeded and before the directory is opened - the
    /// residual create→open window. A gate substitutes the directory here to
    /// exercise the `lstat`/`fstat` agreement check and the identity-bound
    /// cleanup.
    AfterCreate,
}

/// Test seam for the residual create→open window and for no-clobber
/// publication.
///
/// `creation_seam` fires twice per directory this call actually creates (once
/// per [`CreationPhase`]), and never for a directory that already existed.
/// Production always passes a no-op.
#[doc(hidden)]
pub fn begin_persistent_profile_tree_with_creation_seam(
    root: &Path,
    relative: &Path,
    our_uid: Option<u32>,
    gate: impl FnMut(ProvisionCheckpoint<'_>) -> Result<(), String>,
    creation_seam: impl FnMut(CreationPhase, &Path),
) -> Result<ProfileProvision, ProvisionError> {
    begin_persistent_profile_tree_inner(root, relative, our_uid, gate, creation_seam, |_, _| {})
}

/// Where in the adoption of one *existing* over-permissive owned directory a
/// [`begin_persistent_profile_tree_with_adoption_seam`] hook fires.
///
/// The tightening of an owned permissive directory to 0700 is bound to the
/// inode `symlink_metadata` validated, not to the pathname. These two
/// phases are the substitution seams the acceptance criteria exercise: a
/// same-uid process rebinding the name at either phase must not cause a chmod
/// of a symlink target, a foreign inode, or a replacement directory.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdoptionPhase {
    /// After the no-follow `lstat` validated an existing permissive owned
    /// directory, and before it is opened. A gate rebinds the name here to
    /// prove the open is identity-checked against the validated inode.
    BeforeOpen,
    /// After the open proved the descriptor holds the validated inode, and
    /// before the chmod. A gate rebinds the name here to prove the chmod goes
    /// through the held descriptor (`fchmod`), never the pathname.
    AfterOpen,
}

/// Test seam for the identity-bound tightening of an existing over-permissive
/// owned profile directory.
///
/// `adoption_seam` fires twice - once per [`AdoptionPhase`] - for each existing
/// owned directory this call tightens from a permissive mode to 0700, and never
/// for a fresh directory or an already-0700 directory. Production always passes
/// a no-op.
#[doc(hidden)]
pub fn begin_persistent_profile_tree_with_adoption_seam(
    root: &Path,
    relative: &Path,
    our_uid: Option<u32>,
    gate: impl FnMut(ProvisionCheckpoint<'_>) -> Result<(), String>,
    adoption_seam: impl FnMut(AdoptionPhase, &Path),
) -> Result<ProfileProvision, ProvisionError> {
    begin_persistent_profile_tree_inner(root, relative, our_uid, gate, |_, _| {}, adoption_seam)
}

fn begin_persistent_profile_tree_inner(
    root: &Path,
    relative: &Path,
    our_uid: Option<u32>,
    mut gate: impl FnMut(ProvisionCheckpoint<'_>) -> Result<(), String>,
    mut creation_seam: impl FnMut(CreationPhase, &Path),
    mut adoption_seam: impl FnMut(AdoptionPhase, &Path),
) -> Result<ProfileProvision, ProvisionError> {
    // Materialise the full plan before the first mutation. Besides making the
    // transaction auditable, this gives fault injection a stable step count.
    let mut paths = vec![root.to_path_buf()];
    let mut cur = root.to_path_buf();
    for comp in relative.components() {
        cur.push(comp);
        paths.push(cur.clone());
    }
    let data = cur.join("data");
    let cache = cur.join("cache");
    paths.push(data.clone());
    paths.push(cache.clone());

    let mut created = Vec::new();
    let mut adopted = Vec::new();
    let total = paths.len();
    for (index, path) in paths.iter().enumerate() {
        let secured = secure_ensure_dir_with_uid_outcome(
            path,
            our_uid,
            &mut creation_seam,
            &mut adoption_seam,
        );
        match secured {
            Ok(Some(fd)) => created.push(CreatedDir {
                path: path.clone(),
                fd,
            }),
            Ok(None) => adopted.push(path.clone()),
            Err(error) => return rollback_created(created, adopted, error),
        }
        if let Err(label) = gate(ProvisionCheckpoint { index, total, path }) {
            return rollback_created(
                created,
                adopted,
                ProvisionError::FaultInjected {
                    path: path.clone(),
                    label,
                },
            );
        }
    }
    Ok(ProfileProvision {
        paths: ProfilePaths { data, cache },
        created,
        adopted,
    })
}

/// One completed directory step observed by the transactional fault seam.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct ProvisionCheckpoint<'a> {
    /// Zero-based step index.
    pub index: usize,
    /// Total number of directory steps in this transaction.
    pub total: usize,
    /// Directory secured by this step.
    pub path: &'a Path,
}

fn rollback_created(
    created: Vec<CreatedDir>,
    adopted: Vec<PathBuf>,
    cause: ProvisionError,
) -> Result<ProfileProvision, ProvisionError> {
    match rollback_paths(created, &adopted, &cause.to_string()) {
        Ok(()) => Err(cause),
        Err(error) => Err(error),
    }
}

fn rollback_paths(
    mut created: Vec<CreatedDir>,
    adopted: &[PathBuf],
    cause: &str,
) -> Result<(), ProvisionError> {
    let mut leftovers = Vec::new();
    let mut substituted = Vec::new();
    let mut retained = Vec::new();
    while let Some(entry) = created.pop() {
        let CreatedDir { path, .. } = &entry;
        let path = path.clone();
        // Deepest-first: if a descendant of `path` was refused as substituted,
        // `remove_dir_all(path)` would destroy that replacement through the
        // ancestor. Retain the ancestor instead of laundering the refusal.
        // Sabotage: delete this block and both substitution gates redden,
        // because the replacement inode is deleted via its parent.
        // The same retention applies to an adopted directory: a racing
        // instance can publish `<profile>/data` between the `lstat` and the
        // `mkdir` of `<profile>`, so an ancestor created here can hold data this
        // transaction never owned.
        // Sabotage: drop `adopted` from this condition and
        // `racing_winner_at_the_final_path_is_adopted_not_clobbered` reddens,
        // because the winner's directory is deleted through its parent.
        if substituted
            .iter()
            .chain(adopted.iter())
            .any(|keep: &PathBuf| keep.starts_with(&path))
        {
            retained.push(path);
            continue;
        }
        // Identity, not pathname, and read from the descriptor this code has held
        // open since creation - never from a value cached before the caller
        // blocked in backend construction. `fstat` of the pinned inode is
        // compared against `lstat` of the pathname; only agreement authorises a
        // recursive delete. As with `remove_if_identity_matches`, POSIX leaves
        // a residual same-uid rebind window between this observation and
        // `remove_dir_all`; this is identity validation, not unlink-by-inode.
        // Sabotage: replace this match with an unconditional removal (drop the
        // identity comparison) and both substitution gates redden.
        let Ok(identity) = entry.pinned_identity() else {
            // This code cannot even fstat what this code holds: fail closed, delete nothing.
            leftovers.push(path);
            continue;
        };
        match DirIdentity::observe(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                leftovers.push(path);
                continue;
            }
            Ok(observed) if observed != identity => {
                substituted.push(path);
                continue;
            }
            Ok(_) => {}
        }
        // A downstream backend can create cookies or cache files before its
        // constructor reports failure. Because `path` is recorded only when
        // this transaction created it, that partial subtree belongs to the
        // failed attempt and must be removed too. Never recurse into a path
        // that predated the transaction.
        if let Err(error) = std::fs::remove_dir_all(&path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            leftovers.push(path);
        }
    }
    // A later ancestor cleanup may also remove a descendant whose own removal
    // initially failed, so report only paths that genuinely remain.
    leftovers.retain(|path| std::fs::symlink_metadata(path).is_ok());
    if !substituted.is_empty() {
        substituted.reverse();
        retained.reverse();
        leftovers.reverse();
        // Both halves survive: a substitution refusal never swallows the
        // directories this transaction created and failed to remove.
        // Sabotage: drop `leftovers` from this variant and
        // `substitution_refusal_still_reports_leftovers` reddens.
        return Err(ProvisionError::RollbackSubstituted {
            cause: cause.to_owned(),
            substituted,
            retained,
            leftovers,
        });
    }
    if leftovers.is_empty() {
        Ok(())
    } else {
        leftovers.reverse();
        Err(ProvisionError::RollbackFailed {
            cause: cause.to_owned(),
            leftovers,
        })
    }
}

/// Ensure `path` is a user-private, real directory this code owns - creating it 0700
/// if absent, tightening its mode if it is owned by the current user but permissive, and refusing
/// otherwise. See the module docs for the seven decisions.
///
/// # Errors
///
/// [`ProvisionError`] - the exact variant records which guard rejected the
/// directory.
pub fn secure_ensure_dir(path: &Path) -> Result<(), ProvisionError> {
    secure_ensure_dir_with_uid(path, current_uid())
}

/// Test seam for [`secure_ensure_dir`]; see
/// [`provision_persistent_profile_tree_with_uid`].
///
/// # Errors
///
/// As [`secure_ensure_dir`].
#[doc(hidden)]
pub fn secure_ensure_dir_with_uid(path: &Path, our_uid: Option<u32>) -> Result<(), ProvisionError> {
    secure_ensure_dir_with_uid_outcome(path, our_uid, &mut |_, _| {}, &mut |_, _| {}).map(|_| ())
}

/// Secure one directory and, when this call created it, return the open
/// descriptor pinning the inode it created (`None` when an existing secure
/// directory was adopted).
///
/// The descriptor is deliberately private: callers need the invariant, while
/// the profile-tree transaction needs creation provenance *bound to a live
/// inode* so rollback can neither delete a directory that predated the
/// operation nor a replacement that took the pathname while the caller blocked
/// downstream.
fn secure_ensure_dir_with_uid_outcome(
    path: &Path,
    our_uid: Option<u32>,
    creation_seam: &mut dyn FnMut(CreationPhase, &Path),
    adoption_seam: &mut dyn FnMut(AdoptionPhase, &Path),
) -> Result<Option<std::fs::File>, ProvisionError> {
    // `symlink_metadata` - never `metadata`. `metadata` would follow a
    // symlink and report the target's type: a symlinked component would then
    // pass as "a directory" and be adopted silently. Sabotage: change this to
    // `std::fs::metadata` and `symlink_root_is_refused` reddens.
    match std::fs::symlink_metadata(path) {
        Ok(md) => enforce_existing(path, &md, our_uid, adoption_seam).map(|()| None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_fresh_with_uid(path, our_uid, creation_seam)
        }
        Err(e) => Err(ProvisionError::Io {
            path: path.to_path_buf(),
            error: e.to_string(),
        }),
    }
}

/// A directory (or non-directory) already lives at `path`; check ownership,
/// type, and mode.
fn enforce_existing(
    path: &Path,
    md: &std::fs::Metadata,
    our_uid: Option<u32>,
    adoption_seam: &mut dyn FnMut(AdoptionPhase, &Path),
) -> Result<(), ProvisionError> {
    use std::os::unix::fs::MetadataExt;

    let ft = md.file_type();
    if ft.is_symlink() {
        // Sabotage: delete this branch and `symlink_root_is_refused` /
        // `symlink_intermediate_is_refused` / `symlink_leaf_is_refused` all
        // redden.
        return Err(ProvisionError::SymlinkedComponent(path.to_path_buf()));
    }
    if !ft.is_dir() {
        // Sabotage: delete this branch and `non_directory_collision_is_refused`
        // reddens.
        return Err(ProvisionError::NonDirectory(path.to_path_buf()));
    }
    let dir_uid = md.uid();
    let Some(our_uid) = our_uid else {
        // Sabotage: substitute `Some(dir_uid)` here and
        // `owner_unverifiable_is_refused` reddens.
        return Err(ProvisionError::OwnerUnverifiable);
    };
    if dir_uid != our_uid {
        // Sabotage: remove this check and `foreign_owned_dir_is_refused`
        // reddens.
        return Err(ProvisionError::ForeignOwner {
            path: path.to_path_buf(),
            dir_uid,
            our_uid,
        });
    }
    let mode = md.mode() & 0o7777;
    if mode & 0o077 != 0 {
        // Over-permissive but owned by the current user: tighten to 0700. The tightening is bound to
        // the exact inode `md` (an `lstat`) validated, never to the pathname -
        // otherwise a same-uid process could rebind the name between this
        // validation and the chmod and this code would tighten a symlink target, a
        // foreign inode, or a replacement directory.
        // Sabotage: replace this call with `Ok(())` and
        // `permissive_mode_is_tightened_not_refused` reddens (mode stays lax).
        tighten_owned_permissive_dir(path, md, our_uid, mode, adoption_seam)?;
    }
    Ok(())
}

/// Open `path` as a directory descriptor that never follows a final symlink,
/// never blocks, and is close-on-exec.
///
/// The flags come from the ONE shared platform table
/// ([`enzui_security::platform`]) rather than a second near-duplicate:
///
/// * `O_NOFOLLOW` - the *kernel* refuses a final-component symlink (`ELOOP`);
///   a symlink target is never opened, `fstat`ed or chmodded. The kernel
///   refuses it at open, not an after-the-fact `lstat`/`fstat` reconciliation.
/// * `O_DIRECTORY` - the kernel refuses a non-directory (`ENOTDIR`) before the
///   chmod through the descriptor; a same-uid actor cannot swap a file in
///   for the validated directory and have it tightened.
/// * `O_NONBLOCK` - a read-only `open(2)` of a planted FIFO with no writer would
///   otherwise block *inside* the open, before any check runs.
/// * close-on-exec - set by `std` on every descriptor it opens, so no child of
///   this process inherits the tightening handle. (The platform table therefore carries
///   no `O_CLOEXEC` constant: `std` already guarantees it.)
///
/// An open failure is characterised by an `lstat` of the pathname so the caller
/// gets a precise typed refusal (a symlink refused by `O_NOFOLLOW`, a
/// non-directory refused by `O_DIRECTORY`, or a generic I/O error). Nothing is
/// modified on any failure path.
fn open_validated_dir_nofollow(path: &Path) -> Result<std::fs::File, ProvisionError> {
    use std::os::unix::fs::OpenOptionsExt;

    // These flags are the mandated kernel-level early refusal (finding 1): a
    // symlink or non-directory at the pathname is refused inside `open(2)`, so
    // the target is never opened, `fstat`ed, or chmodded. They are
    // defense-in-depth beside the `fstat`-identity and post-chmod
    // reconciliation guards, which independently refuse a substitution even if
    // a flag were dropped (that redundancy is deliberate, not dead weight);
    // reverting the whole tightening to a naive pathname `set_permissions` is
    // what reddens `adoption_refuses_a_symlink_substituted_before_open`.
    let flags = enzui_security::platform::libc_o_nofollow()
        | enzui_security::platform::libc_o_directory()
        | enzui_security::platform::libc_o_nonblock();
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|e| classify_open_failure(path, &e))
}

/// Turn a no-follow directory-open failure into a precise typed refusal by
/// re-observing the pathname with `lstat` (which never follows the link).
fn classify_open_failure(path: &Path, err: &std::io::Error) -> ProvisionError {
    match std::fs::symlink_metadata(path) {
        Ok(seen) if seen.file_type().is_symlink() => {
            // `O_NOFOLLOW` refused a final-component symlink.
            ProvisionError::SymlinkedComponent(path.to_path_buf())
        }
        Ok(seen) if !seen.file_type().is_dir() => {
            // `O_DIRECTORY` refused a non-directory.
            ProvisionError::NonDirectory(path.to_path_buf())
        }
        _ => ProvisionError::Io {
            path: path.to_path_buf(),
            error: format!("permissive profile directory could not be opened no-follow: {err}"),
        },
    }
}

/// Tighten an existing owned directory that `lstat` reported as permissive
/// (0755/0770/…) down to 0700, binding every step to the exact inode `lstat`
/// validated instead of to the pathname.
///
/// [`enforce_existing`] validated `validated` with `symlink_metadata` - a
/// no-follow `lstat`. A same-uid process can rebind the name to a symlink or a
/// foreign / replacement directory between that validation and this tightening;
/// a pathname `set_permissions` follows symlinks and would then chmod whatever
/// the name now points at, and the caller would continue without re-observing
/// the directory identity/mode. The same substitution class is handled for
/// rollback and adoption.
///
/// The sequence, hardened to bind every mutation to the validated inode:
///
/// 1. `BeforeOpen` seam, then open with `O_NOFOLLOW | O_DIRECTORY |
///    O_NONBLOCK` (close-on-exec via `std`). A symlink swapped in is refused by
///    the kernel (`ELOOP`); a non-directory by `ENOTDIR`. A symlink target is
///    never opened.
/// 2. Authoritative `fstat` of the descriptor supplies type, uid, mode and
///    `(dev, ino)` - every subsequent decision reads these, never the stale
///    `lstat`. A descriptor whose inode differs from the one `lstat` validated
///    is a same-uid direct-directory swap between `lstat` and `open`, and is
///    refused (never chmodded, because it is no longer the validated inode).
/// 3. `AfterOpen` seam, then chmod *through* the descriptor (`fchmod` via
///    [`std::fs::File::set_permissions`]), then re-`fstat` to confirm the mode
///    landed. `fchmod` acts on the pinned inode, so this tightens exactly the
///    validated object regardless of what now owns the pathname.
/// 4. Post-chmod `lstat` reconciliation. Because the value finally returned
///    is a *pathname* the backend re-opens, the name must still resolve to
///    the very inode that was tightened and to a safe type. A substitution planted
///    at the `AfterOpen` seam is therefore refused here - `fchmod` already
///    tightened only the held inode, so the replacement is never touched, and
///    the returned [`ProfilePaths`] can never denote it.
///
/// A rebind at any step is refused, never followed - this code never chmods a symlink
/// target, foreign inode, or replacement.
///
/// A residual same-uid window survives between the final `lstat` and the
/// backend's own re-open, exactly as documented for the create→open window;
/// this narrows it to a same-uid actor (no privilege boundary - the parent is
/// 0700 and owned by the current user) and never widens it.
fn tighten_owned_permissive_dir(
    path: &Path,
    validated: &std::fs::Metadata,
    our_uid: u32,
    observed_mode: u32,
    adoption_seam: &mut dyn FnMut(AdoptionPhase, &Path),
) -> Result<(), ProvisionError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let validated_identity = DirIdentity::of(validated);

    // Test seam: a substitution planted here lands between `lstat` validation
    // and the no-follow open below.
    adoption_seam(AdoptionPhase::BeforeOpen, path);

    // Real `O_NOFOLLOW | O_DIRECTORY | O_NONBLOCK` open: the kernel refuses a
    // symlink or a non-directory before this code can touch anything.
    let fd = open_validated_dir_nofollow(path)?;

    // Authoritative identity/type/uid/mode from `fstat`, never the stale
    // `lstat`.
    let opened = fd.metadata().map_err(|e| ProvisionError::Io {
        path: path.to_path_buf(),
        error: format!("permissive profile directory could not be fstat'ed: {e}"),
    })?;
    let fd_identity = DirIdentity::of(&opened);

    // `O_DIRECTORY` already guarantees a directory, but the authoritative check
    // is the `fstat` type: read it here rather than trust the open flag.
    if !opened.file_type().is_dir() {
        return Err(ProvisionError::NonDirectory(path.to_path_buf()));
    }
    if opened.uid() != our_uid {
        // Authoritative owner check from `fstat` (finding 2), defense-in-depth
        // beside the `lstat`-side check in `enforce_existing`
        // (`adoption_refuses_a_foreign_owned_permissive_tree`). A *true* fd-side
        // foreign inode - one whose `lstat` owner passed but whose `fstat` owner
        // differs - requires a chown across the open, i.e. a second uid or
        // `CAP_CHOWN`, so it is not constructible in a single-uid test; this
        // branch is verified by the `lstat`-side gate.
        return Err(ProvisionError::ForeignOwner {
            path: path.to_path_buf(),
            dir_uid: opened.uid(),
            our_uid,
        });
    }
    // The descriptor must hold the very inode `lstat` validated. A different
    // (dev, ino) is a same-uid directory swapped in between `lstat` and `open`
    // - a replacement this code must never chmod.
    // Sabotage: delete this block and
    // `adoption_refuses_a_direct_directory_substituted_before_open` reddens,
    // because the replacement directory is tightened.
    if fd_identity != validated_identity {
        return Err(refusal_for_rebound_path(path));
    }

    // Test seam: a substitution planted here lands between the open and the
    // chmod. The descriptor already pins the validated inode, so the `fchmod`
    // below tightens exactly that inode; the post-chmod `lstat` reconciliation
    // then refuses the substituted pathname.
    adoption_seam(AdoptionPhase::AfterOpen, path);

    // Apply the tightening *through* the held descriptor (`fchmod`), never the
    // pathname. `std::fs::set_permissions(path, …)` follows a symlink and would
    // chmod whatever the name now points at; `File::set_permissions` chmods the
    // inode the descriptor holds and nothing else.
    // Sabotage: change this to
    // `std::fs::set_permissions(path, std::fs::Permissions::from_mode(PROFILE_DIR_MODE))`
    // and `adoption_refuses_a_symlink_substituted_after_open` reddens, because
    // the rebind target (decoy) is tightened instead of the held inode.
    fd.set_permissions(std::fs::Permissions::from_mode(PROFILE_DIR_MODE))
        .map_err(|e| ProvisionError::ChmodFailed {
            path: path.to_path_buf(),
            mode: observed_mode,
            error: e.to_string(),
        })?;

    // Revalidate the resulting mode from the descriptor: the monotonic
    // tightening must have landed owner-only permission bits. `fchmod` clears
    // `S_ISGID`, so a setgid parent's 2755 becomes 0700; comparing only the
    // permission bits (`& 0o777`) keeps that legitimate.
    // Sabotage: change `PROFILE_DIR_MODE` on the right of this comparison to
    // `observed_mode` and `permissive_mode_is_tightened_not_refused` reddens
    // for a directory whose chmod was silently a no-op.
    let after = fd.metadata().map_err(|e| ProvisionError::Io {
        path: path.to_path_buf(),
        error: format!("tightened profile directory could not be re-fstat'ed: {e}"),
    })?;
    if after.mode() & 0o777 != PROFILE_DIR_MODE {
        return Err(ProvisionError::ChmodFailed {
            path: path.to_path_buf(),
            mode: after.mode() & 0o7777,
            error: format!(
                "chmod through descriptor left mode {:04o}, not {:04o}",
                after.mode() & 0o777,
                PROFILE_DIR_MODE
            ),
        });
    }

    // Post-chmod `lstat` reconciliation. The value this code returns is a pathname the
    // backend re-opens, so the name must STILL denote the inode this code just
    // tightened and a safe (directory) type. A substitution planted at the
    // `AfterOpen` seam is refused here; `fchmod` already tightened only the held
    // inode, so the replacement is never touched.
    // Sabotage: delete this block and
    // `adoption_refuses_a_symlink_substituted_after_open` /
    // `adoption_refuses_a_direct_directory_substituted_after_open` redden,
    // because a post-open substitution is returned as success and the returned
    // ProfilePaths then names the replacement.
    reconcile_path_still_names(path, fd_identity)?;

    Ok(())
}

/// After the descriptor-bound chmod, confirm the pathname still resolves
/// (no-follow) to `identity` and to a directory. Refuse otherwise, touching
/// nothing: whatever now owns the name is not the inode this code tightened, so a
/// returned [`ProfilePaths`] must not denote it.
fn reconcile_path_still_names(path: &Path, identity: DirIdentity) -> Result<(), ProvisionError> {
    match std::fs::symlink_metadata(path) {
        Ok(seen) if seen.file_type().is_symlink() => {
            Err(ProvisionError::SymlinkedComponent(path.to_path_buf()))
        }
        Ok(seen) if !seen.file_type().is_dir() => {
            Err(ProvisionError::NonDirectory(path.to_path_buf()))
        }
        Ok(seen) if DirIdentity::of(&seen) != identity => Err(ProvisionError::Io {
            path: path.to_path_buf(),
            error: "the profile directory was replaced after it was tightened; the pathname no \
                    longer names the validated inode, so it is refused rather than returned"
                .to_string(),
        }),
        Ok(_) => Ok(()),
        Err(e) => Err(ProvisionError::Io {
            path: path.to_path_buf(),
            error: format!("tightened profile directory vanished before it could be returned: {e}"),
        }),
    }
}

/// Characterise a pathname that was rebound to a different inode between `lstat`
/// validation and the no-follow open, for a precise typed refusal. Nothing is
/// modified or deleted on this path - whatever now owns the name is not the
/// inode this code validated, so this code neither chmods nor deletes it.
///
/// The no-follow open already refused a symlink (`O_NOFOLLOW`) and a
/// non-directory (`O_DIRECTORY`) at the kernel, so reaching here means the name
/// resolved to a *different real directory* than `lstat` saw; the `lstat` below
/// is nonetheless kept so a concurrent third swap is still reported precisely.
fn refusal_for_rebound_path(path: &Path) -> ProvisionError {
    match std::fs::symlink_metadata(path) {
        Ok(seen) if seen.file_type().is_symlink() => {
            ProvisionError::SymlinkedComponent(path.to_path_buf())
        }
        Ok(seen) if !seen.file_type().is_dir() => ProvisionError::NonDirectory(path.to_path_buf()),
        Ok(_) => ProvisionError::Io {
            path: path.to_path_buf(),
            error: "the profile directory validated by lstat was replaced by another directory \
                    before it could be tightened; refusing to chmod the replacement"
                .to_string(),
        },
        Err(e) => ProvisionError::Io {
            path: path.to_path_buf(),
            error: format!("profile directory vanished before it could be tightened: {e}"),
        },
    }
}

/// `path` did not exist: create it 0700 via `mkdir(2)` with an explicit mode
/// and return the descriptor pinning the created inode; a racing winner at the
/// same pathname is adopted (never replaced) and returns `None`.
///
/// ## Publication
///
/// `mkdir(2)` at the final pathname is the no-clobber publication primitive:
/// atomic, and `EEXIST` rather than replacement when someone got there first.
/// The `EEXIST` arm redispatches through [`enforce_existing`], so the winner is
/// adopted if it is a secure directory this code owns and refused otherwise - in
/// neither case is it deleted. See the module docs for why `rename(2)` is not
/// used.
///
/// ## Pinning and validation
///
/// The created directory is opened immediately and every subsequent decision is
/// made from that descriptor: `fstat` supplies type, owner, mode and identity,
/// and an `lstat` of the pathname must agree with it. That comparison is the
/// safe-`std` equivalent of `O_NOFOLLOW` - a symlink swapped in after `mkdir`
/// reports the *link's* identity, which cannot equal the directory's - and it
/// is what makes the residual create→open window (module docs) refuse every
/// observable substitution.
///
/// ## Mode
///
/// `DirBuilderExt::mode(0o700)` is the load-bearing call: without it, `mkdir(2)`
/// requests the default 0777 which the process umask masks to (typically)
/// 0755, i.e. world-readable cookies. 0700 has no group/other bits, so any
/// sane umask leaves the observed mode at 0700; the gate
/// `fresh_dir_is_0700_under_default_umask` proves the disk consequence.
fn create_fresh_with_uid(
    path: &Path,
    our_uid: Option<u32>,
    creation_seam: &mut dyn FnMut(CreationPhase, &Path),
) -> Result<Option<std::fs::File>, ProvisionError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    // Deterministic test seam. Production always passes a no-op.
    // Sabotage: delete this line and `creation_seam_observes_both_phases`
    // reddens because no `BeforeCreate` event is recorded.
    creation_seam(CreationPhase::BeforeCreate, path);

    let mut builder = std::fs::DirBuilder::new();
    // Sabotage: delete this line and `fresh_dir_is_0700_under_default_umask`
    // reddens, because `mkdir(2)` then requests 0777 and umask 022 leaves
    // the directory at 0755.
    builder.mode(PROFILE_DIR_MODE);

    if let Err(e) = builder.create(path) {
        // `mkdir(2)` never replaces: `EEXIST` means someone else published
        // first (a racing instance of the app, or a symlink planted between
        // the `lstat` and this call). Redispatch through the existing-entry
        // checks so the winner is adopted or refused - never deleted.
        // Sabotage: remove the winner here and retry the `mkdir`, and
        // `racing_winner_at_the_final_path_is_adopted_not_clobbered` plus
        // `concurrent_provisioning_never_destroys_another_instances_data`
        // both redden.
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            return match std::fs::symlink_metadata(path) {
                Ok(md) => enforce_existing(path, &md, our_uid, &mut |_, _| {}).map(|()| None),
                Err(e) => Err(ProvisionError::Io {
                    path: path.to_path_buf(),
                    error: e.to_string(),
                }),
            };
        }
        return Err(ProvisionError::Io {
            path: path.to_path_buf(),
            error: e.to_string(),
        });
    }

    // Deterministic test seam: runs in the residual create→open window.
    // Sabotage: delete this line and `creation_seam_observes_both_phases`
    // reddens because no `AfterCreate` event is recorded.
    creation_seam(CreationPhase::AfterCreate, path);

    // Open once, then decide everything from the descriptor. There is no
    // atomic create-and-open for directories, so this is the window the module
    // docs describe; the `lstat`/`fstat` agreement below is what refuses every
    // observable substitution inside it.
    let fd = std::fs::File::open(path).map_err(|e| ProvisionError::Io {
        path: path.to_path_buf(),
        error: format!("created directory could not be opened for pinning: {e}"),
    })?;
    let md = fd.metadata().map_err(|e| ProvisionError::Io {
        path: path.to_path_buf(),
        error: format!("created directory could not be fstat'ed: {e}"),
    })?;
    let identity = DirIdentity::of(&md);

    // `O_NOFOLLOW` in safe std: the pathname must still denote the very inode
    // the descriptor holds. A symlink swapped in after `mkdir` reports the
    // link's own identity here and can never match.
    // Sabotage: delete this block and
    // `creation_refuses_a_symlink_substituted_after_mkdir` reddens - the
    // symlink target's identity is pinned and published as the profile
    // directory.
    match DirIdentity::observe(path) {
        Ok(seen) if seen == identity => {}
        Ok(_) => {
            let seen_md = std::fs::symlink_metadata(path).map_err(|e| ProvisionError::Io {
                path: path.to_path_buf(),
                error: e.to_string(),
            })?;
            // Nothing is removed on this branch: whatever now owns the
            // pathname is not the inode created here.
            return Err(if seen_md.file_type().is_symlink() {
                ProvisionError::SymlinkedComponent(path.to_path_buf())
            } else if seen_md.file_type().is_dir() {
                ProvisionError::Io {
                    path: path.to_path_buf(),
                    error: "the directory we created was replaced by another directory before it \
                            could be opened; refusing to adopt or delete it"
                        .to_string(),
                }
            } else {
                ProvisionError::NonDirectory(path.to_path_buf())
            });
        }
        Err(e) => {
            return Err(ProvisionError::Io {
                path: path.to_path_buf(),
                error: format!("created directory vanished before it could be pinned: {e}"),
            });
        }
    }

    // From here the pathname provably denotes the pinned inode, so any cleanup
    // below is identity-bound by construction and still re-checks.
    if !md.file_type().is_dir() {
        remove_if_identity_matches(path, identity);
        return Err(ProvisionError::NonDirectory(path.to_path_buf()));
    }
    let Some(uid) = our_uid else {
        remove_if_identity_matches(path, identity);
        return Err(ProvisionError::OwnerUnverifiable);
    };
    if md.uid() != uid {
        remove_if_identity_matches(path, identity);
        return Err(ProvisionError::ForeignOwner {
            path: path.to_path_buf(),
            dir_uid: md.uid(),
            our_uid: uid,
        });
    }
    // Permission bits only. `mkdir(2)` in a set-group-id parent inherits
    // `S_ISGID`, so a freshly created directory legitimately reads 2700 - which
    // is still owner-only. `enforce_existing` masks the same way; comparing
    // `mode & 0o7777` here would refuse every first-run provision under a
    // setgid parent.
    // Sabotage: widen this mask to `0o7777` and `setgid_parent_is_accepted`
    // reddens with "unexpected mode 2700".
    if md.mode() & 0o777 != PROFILE_DIR_MODE {
        remove_if_identity_matches(path, identity);
        return Err(ProvisionError::Io {
            path: path.to_path_buf(),
            error: format!(
                "created directory has unexpected permission bits {:04o} (expected {:04o})",
                md.mode() & 0o777,
                PROFILE_DIR_MODE,
            ),
        });
    }

    Ok(Some(fd))
}

/// The own effective uid, or `None` if it cannot be determined.
///
/// The workspace forbids `unsafe`, so a `libc::geteuid` binding is not
/// available here; the fallback ladder mirrors
/// `enzui_security::runtime_dir::current_uid`:
///
/// 1. `/proc/self` - a Linux `/proc/<pid>` directory is owned by the process's
///    uid, so [`std::fs::metadata`] reports it with no filesystem write.
/// 2. Otherwise `None` - treated as [`ProvisionError::OwnerUnverifiable`], not
///    "the check passed".
///
/// A wrapper is provided so this file has no `enzui-security` dependency
/// hard-coded in signatures; the crate does depend on it, but tests can pass
/// a fixed uid through the `_with_uid` seams above.
#[cfg(unix)]
#[must_use]
pub fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = std::fs::metadata("/proc/self") {
        return Some(meta.uid());
    }
    None
}

#[cfg(not(unix))]
#[must_use]
pub fn current_uid() -> Option<u32> {
    None
}
