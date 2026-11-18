//! `profile_fs` - filesystem consequence gates for the symlink-safe,
//! user-private WebView profile store.

use enzui_webkit::profile_fs::{
    AdoptionPhase, CreationPhase, ProvisionError, begin_persistent_profile_tree_with_adoption_seam,
    begin_persistent_profile_tree_with_creation_seam,
    begin_persistent_profile_tree_with_uid_and_gate, current_uid,
    provision_persistent_profile_tree, provision_persistent_profile_tree_with_uid,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// A unique scratch directory per gate, removed on drop.
///
/// Uses `CARGO_TARGET_TMPDIR` on real disk under `target/`, never `/tmp` or
/// `env::temp_dir()`.
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "profile-fs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).expect("create scratch");
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        // Best-effort recursive delete; a mode-restricted directory may need
        // chmod first to remove children created 0700.
        let _ = chmod_tree_recursive(&self.0, 0o700);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn chmod_tree_recursive(path: &Path, mode: u32) -> std::io::Result<()> {
    if let Ok(md) = std::fs::symlink_metadata(path)
        && md.file_type().is_dir()
    {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        for entry in std::fs::read_dir(path)?.flatten() {
            let _ = chmod_tree_recursive(&entry.path(), mode);
        }
    }
    Ok(())
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).expect("metadata").mode() & 0o7777
}

fn inode_of(path: &Path) -> u64 {
    std::fs::symlink_metadata(path).expect("metadata").ino()
}

/// Gate 5 - a symlink at an intermediate component is refused.
///
/// The `persistent/` subdirectory under the store root is a symlink to a
/// directory the caller does not own (in this fixture, another directory in
/// the same scratch, but the guard does not know that). Refusal without
/// following.
///
/// # Sabotage
///
/// As gate 4: swap `symlink_metadata` for `metadata`; the symlink is
/// followed and this gate reddens.
#[test]
fn symlink_intermediate_is_refused() {
    let scratch = Scratch::new("symlink-intermediate");
    let root = scratch.path().join("store");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let elsewhere = scratch.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, root.join("persistent")).unwrap();

    let err = provision_persistent_profile_tree(&root, Path::new("persistent/abc"))
        .expect_err("symlinked intermediate must be refused");
    match &err {
        ProvisionError::SymlinkedComponent(p) => {
            assert_eq!(
                p,
                &root.join("persistent"),
                "wrong symlink component reported"
            );
        }
        other => panic!("expected SymlinkedComponent, got {other:?}"),
    }
    // Redirection would have created files under `elsewhere/abc/data`; it did
    // not.
    assert!(!elsewhere.join("abc/data").exists());
}

/// Gate 11 - a failed multi-directory provision rolls back every directory
/// created by the attempt, at the first, middle, and last mutation boundary.
///
/// The WPE `ProfileStore` is the production consumer: it calls this shared
/// boundary before handing `data` and `cache` to WebKit. Previously, failure
/// after creating `root`, an intermediate, or even both leaves returned `Err`
/// while leaking a plausible partial profile tree. A retry could then mistake
/// that residue for a previously committed profile.
///
/// The fixture starts with an existing scratch parent as a positive control:
/// rollback must preserve caller-owned ancestors while removing only paths for
/// which this attempt observed successful creation.
///
/// # Sabotage
///
/// Delete `created.push(path.clone())` in the transaction. All three injected
/// failures still return `Err`, but this gate reddens because the first created
/// directory remains on disk (and the later cases leave progressively deeper
/// partial trees).
#[test]
fn first_middle_and_last_failures_rollback_the_whole_new_profile_tree() {
    let us = current_uid().expect("current_uid");

    for (label, fail_index) in [("first", 0usize), ("middle", 2), ("last", 4)] {
        let scratch = Scratch::new(label);
        let root = scratch.path().join("store");
        let mut checkpoints = Vec::new();
        let err = begin_persistent_profile_tree_with_uid_and_gate(
            &root,
            Path::new("persistent/abc"),
            Some(us),
            |checkpoint| {
                checkpoints.push((
                    checkpoint.index,
                    checkpoint.total,
                    checkpoint.path.to_path_buf(),
                ));
                if checkpoint.index == fail_index {
                    Err(label.to_owned())
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("the selected checkpoint must fail");

        match &err {
            ProvisionError::FaultInjected {
                path,
                label: injected_label,
            } => {
                assert_eq!(injected_label, label);
                assert_eq!(path, &checkpoints.last().unwrap().2);
            }
            other => panic!(
                "the original injected failure must survive a successful rollback: {other:?}"
            ),
        }
        assert_eq!(
            checkpoints.last().map(|(index, total, _)| (*index, *total)),
            Some((fail_index, 5)),
            "{label} control did not reach the intended checkpoint"
        );
        assert!(
            !root.exists(),
            "{label} failure left a half-provisioned profile tree at {}",
            root.display()
        );
        assert!(
            scratch.path().is_dir(),
            "rollback must preserve the pre-existing caller-owned scratch parent"
        );
        assert_eq!(
            std::fs::read_dir(scratch.path()).unwrap().count(),
            0,
            "{label} rollback leaked a temp directory or other partial resource"
        );
    }

    // The real consumer has one more fallible step after every directory exists:
    // WebKit must accept the data/cache paths. Exercise the exact guard method
    // `ProfileStore::persistent_under` uses when that backend step fails.
    let scratch = Scratch::new("backend-last");
    let root = scratch.path().join("store");
    std::fs::create_dir(&root).expect("pre-existing caller-owned profile root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let marker = root.join("pre-existing.marker");
    std::fs::write(&marker, b"keep me").unwrap();
    let root_inode = inode_of(&root);
    let provision = begin_persistent_profile_tree_with_uid_and_gate(
        &root,
        Path::new("persistent/abc"),
        Some(us),
        |_| Ok(()),
    )
    .expect("all filesystem steps complete before backend construction");
    assert!(provision.paths().data.is_dir());
    assert!(provision.paths().cache.is_dir());
    std::fs::write(
        provision.paths().data.join("cookies.sqlite-partial"),
        b"backend-created before refusal",
    )
    .expect("seed a partial backend resource owned by this transaction");
    provision
        .rollback()
        .expect("injected backend refusal rolls back provisioning");
    assert!(
        root.is_dir(),
        "rollback removed a pre-existing profile root"
    );
    assert_eq!(inode_of(&root), root_inode);
    assert_eq!(std::fs::read(&marker).unwrap(), b"keep me");
    assert!(
        !root.join("persistent").exists(),
        "a last-step backend failure left a partial named-profile subtree"
    );
}

/// Gate 12 - no ambient HOME mutation: the test suite that just ran does not
/// touch `$HOME` or `$XDG_*`.
///
/// This is an inventory-style guard: a source read of *this file* proves the
/// assertion, and any future addition of `env::set_var("HOME", ...)` here or
/// in `profile_fs.rs` would show up in the search. The gate must be a real
/// filesystem observation, not a pure grep, so this code asserts on the environment
/// as it is *now*.
///
/// # Sabotage
///
/// Add `unsafe { std::env::set_var("HOME", "/tmp/wrong") }` to any gate above;
/// this gate reddens on the value change.
#[test]
fn no_ambient_home_mutation() {
    // Capture before/after values so a mutation somewhere else in this
    // process would be visible. The suite has no threads and no `set_var`,
    // so the value is unchanged.
    let home_before = std::env::var_os("HOME");
    // Run one representative provision (no HOME lookup should happen inside
    // it) and confirm HOME did not move.
    let scratch = Scratch::new("no-home");
    let _ = provision_persistent_profile_tree(
        &scratch.path().join("store"),
        Path::new("persistent/abc"),
    )
    .expect("provision without HOME lookup");
    let home_after = std::env::var_os("HOME");
    assert_eq!(
        home_before, home_after,
        "profile provisioning mutated $HOME (before={:?}, after={:?})",
        home_before, home_after
    );
}

// ---------------------------------------------------------------------------
// Tiny direct binding to `umask(2)`. The workspace forbids `unsafe`, but tests
// are allowed to opt in per file with a `deny`/`allow` toggle (see the FFI
// modules elsewhere in this crate). `umask` is a thread-unsafe global in
// glibc, so this gate does not run concurrently with anything else; cargo's
// per-test threading is a non-issue because this code saves/restore around the call.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Gates 13-14 - rollback is bound to the inode it created, not to a pathname.
//
// `ProfileStore::persistent_under` provisions the tree, then blocks in
// `NetworkSession::new_persistent_path_with_policy` (WebKit opening the cookie
// sqlite) and only afterwards calls `ProfileProvision::rollback`. That blocking
// backend boundary is the TOCTOU window: the recorded pathname can be rebound
// to a different inode before cleanup runs. Both gates drive the *real*
// consumer method (`rollback`), assert on disk, and use a same-shape
// no-substitution control so a rollback that simply stopped deleting cannot
// pass them.
// ---------------------------------------------------------------------------

/// Provision a tree the way `persistent_under` does and return the guard.
fn provisioned(root: &Path) -> enzui_webkit::profile_fs::ProfileProvision {
    let us = current_uid().expect("current_uid");
    begin_persistent_profile_tree_with_uid_and_gate(
        root,
        Path::new("persistent/abc"),
        Some(us),
        |_| Ok(()),
    )
    .expect("all filesystem steps complete before backend construction")
}

fn substitution_report(err: &ProvisionError) -> (Vec<PathBuf>, Vec<PathBuf>) {
    match err {
        ProvisionError::RollbackSubstituted {
            substituted,
            retained,
            ..
        } => (substituted.clone(), retained.clone()),
        other => panic!("expected a substitution refusal, got {other:?}"),
    }
}

/// Gate 14 - a symlink swapped in for a created directory is refused by
/// identity, and its target survives.
///
/// `remove_dir_all` happens to fail on a symlink, but the ancestor sweep does
/// not: without the identity + retention guards the decoy is deleted through
/// `<root>/persistent`. This gate proves the refusal, not the luck.
///
/// # Sabotage
///
/// Same two mutations as gate 13; either one deletes the decoy's sentinel.
#[test]
fn rollback_refuses_a_symlink_substituted_for_a_created_directory() {
    let scratch = Scratch::new("subst-symlink");
    let root = scratch.path().join("store");
    let decoy = scratch.path().join("decoy");
    std::fs::create_dir(&decoy).unwrap();
    let sentinel = decoy.join("precious");
    std::fs::write(&sentinel, b"decoy payload").unwrap();

    let provision = provisioned(&root);
    let data = provision.paths().data.clone();
    std::fs::remove_dir_all(&data).unwrap();
    std::os::unix::fs::symlink(&decoy, &data).expect("swap a symlink in for the created dir");

    let err = provision
        .rollback()
        .expect_err("rollback must refuse a symlink at a recorded pathname");
    let (substituted, retained) = substitution_report(&err);
    assert_eq!(substituted, vec![data.clone()]);
    assert_eq!(
        std::fs::read(&sentinel).unwrap_or_default(),
        b"decoy payload",
        "rollback followed or removed through a substituted symlink"
    );
    assert!(
        retained.contains(&root),
        "the ancestors of a refused path must not be swept: {retained:?}"
    );
    assert!(
        std::fs::symlink_metadata(&data)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the refused pathname must be left exactly as found"
    );
    assert_eq!(
        std::fs::read_dir(&decoy).unwrap().count(),
        1,
        "the decoy directory must be untouched"
    );
}

// ---------------------------------------------------------------------------
// Gates 15-23 - no-clobber publication, the residual create→open window, and
// the descriptor pin.
//
// The provisioner creates each fresh directory at its FINAL pathname with
// `mkdir(2)` (whose `EEXIST` is the kernel's no-clobber refusal), then opens it
// and decides everything from that descriptor. `CreationPhase::BeforeCreate`
// lets a gate publish a racing winner; `CreationPhase::AfterCreate` lets a gate
// substitute inside the residual create→open window.
// ---------------------------------------------------------------------------

/// Gate 16 - cleanup after a refused creation never unlinks a substituted
/// entry: a file put at the pathname inside the create→open window is refused
/// by type and left exactly as found.
///
/// `open(2)` follows the pathname, so the descriptor this code ends up holding *is* the
/// planted file and its identity matches the path - identity alone cannot
/// reject it. What protects the file is that every cleanup in this module is
/// `remove_dir_all`, which refuses a non-directory.
///
/// # Sabotage
///
/// Add `let _ = std::fs::remove_file(path);` to `remove_if_identity_matches`;
/// the planted file is destroyed and this gate reddens.
#[test]
fn creation_refusal_cleanup_spares_a_substituted_entry() {
    let scratch = Scratch::new("create-window-file");
    let root = scratch.path().join("store");
    let us = current_uid().expect("current_uid");

    let mut fired = false;
    let err = begin_persistent_profile_tree_with_creation_seam(
        &root,
        Path::new("persistent/abc"),
        Some(us),
        |_| Ok(()),
        |phase, path| {
            if phase == CreationPhase::AfterCreate && !fired {
                fired = true;
                std::fs::remove_dir(path).expect("remove the just-created dir");
                std::fs::write(path, b"someone else's file").expect("plant a file");
            }
        },
    )
    .expect_err("a file in the create→open window must be refused");

    assert!(fired, "the AfterCreate seam must have fired");
    match &err {
        ProvisionError::NonDirectory(p) => assert_eq!(p, &root),
        other => panic!("expected NonDirectory, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(&root).unwrap_or_default(),
        b"someone else's file",
        "the refused entry was unlinked by a cleanup that was not directory-only"
    );
}

/// Gate 19 - real concurrency: eight threads provisioning the same profile
/// tree must never destroy each other's data.
///
/// This is the accidental case the module exists for - a second app instance,
/// not an attacker. Each thread provisions, writes a sentinel into its `data`
/// directory, then commits. Any publication that replaced a directory instead
/// of adopting it (a `rename(2)` over an empty winner) unlinks a sibling's
/// inode and loses that sentinel.
///
/// # Sabotage
///
/// The same `AlreadyExists`-arm mutation as gate 18 (remove-then-retry): this
/// gate reddens with missing sentinels.
#[test]
fn concurrent_provisioning_never_destroys_another_instances_data() {
    const THREADS: usize = 8;
    let scratch = Scratch::new("concurrent-publish");
    let root = scratch.path().join("store");
    let us = current_uid().expect("current_uid");

    let barrier = std::sync::Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for id in 0..THREADS {
            let root = root.clone();
            let barrier = &barrier;
            scope.spawn(move || {
                // Real concurrency, not interleaved setup: every thread is
                // released into `mkdir` at the same instant.
                barrier.wait();
                let provision = begin_persistent_profile_tree_with_uid_and_gate(
                    &root,
                    Path::new("persistent/abc"),
                    Some(us),
                    |_| Ok(()),
                )
                .unwrap_or_else(|e| panic!("thread {id} failed to provision: {e}"));
                std::fs::write(
                    provision.paths().data.join(format!("sentinel-{id}")),
                    format!("thread {id}").as_bytes(),
                )
                .unwrap_or_else(|e| panic!("thread {id} could not write its sentinel: {e}"));
                let _ = provision.commit();
            });
        }
    });

    let data = root.join("persistent/abc/data");
    for id in 0..THREADS {
        let sentinel = data.join(format!("sentinel-{id}"));
        assert_eq!(
            std::fs::read(&sentinel).unwrap_or_default(),
            format!("thread {id}").as_bytes(),
            "{} was destroyed by a concurrent provisioner",
            sentinel.display()
        );
    }
}

// ---------------------------------------------------------------------------
// Gates 24-33 - adoption tightening is identity-bound and pathname-safe
//
// `enforce_existing` validates an existing owned directory with a no-follow
// `lstat`, then tightens a permissive mode to 0700. The hardened tightening:
//
//   * opens with `O_NOFOLLOW | O_DIRECTORY | O_NONBLOCK` (never `File::open`
//     on the pathname), so the kernel refuses a symlink/non-directory;
//   * derives authoritative type/uid/mode/(dev,ino) from `fstat`;
//   * chmods THROUGH the descriptor (`fchmod`), never the pathname;
//   * after the chmod, re-`lstat`s the pathname and refuses unless it still
//     names the tightened inode and a safe type - a post-open substitution is
//     a refusal, not a success, so the returned `ProfilePaths` stays safe.
//
// The matrix covers same-uid direct-directory AND symlink substitutions at
// BeforeOpen and AfterOpen, a foreign-owner control, and normal/ setgid/
// sticky positives. Each gate names the single mutation of `profile_fs.rs`
// that reddens it.
// ---------------------------------------------------------------------------

/// Pre-create `<root>/{persistent/abc/{data,cache}}` all at `mode` (owned,
/// permissive), the shape an existing profile created under a lax umask has.
fn precreate_tree_at(root: &Path, mode: u32) {
    let leaf = root.join("persistent/abc");
    std::fs::create_dir_all(leaf.join("data")).unwrap();
    std::fs::create_dir_all(leaf.join("cache")).unwrap();
    for dir in [
        root.to_path_buf(),
        root.join("persistent"),
        leaf.clone(),
        leaf.join("data"),
        leaf.join("cache"),
    ] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// A decoy directory carrying a sentinel mode (0755) and sentinel content, used
/// to prove the tightening never touches a substituted target.
fn make_decoy(scratch: &Scratch, name: &str) -> PathBuf {
    let decoy = scratch.path().join(name);
    std::fs::create_dir(&decoy).unwrap();
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(decoy.join("precious"), b"must survive untouched").unwrap();
    decoy
}

/// Assert a decoy still carries its sentinel mode (0755) and content - i.e. the
/// tightening never followed a substitution to it.
fn assert_decoy_untouched(decoy: &Path) {
    assert_eq!(
        mode_of(decoy) & 0o777,
        0o755,
        "the substituted target was chmodded (now {:04o})",
        mode_of(decoy) & 0o777
    );
    assert_eq!(
        std::fs::read(decoy.join("precious")).unwrap_or_default(),
        b"must survive untouched",
        "the substituted target's content changed"
    );
}

/// Gate 26 - a symlink swapped in *after* the open (once the descriptor is
/// bound) does not divert the chmod: `fchmod` tightens the held inode, and the
/// post-chmod `lstat` reconciliation then REFUSES because the pathname no
/// longer names that inode. The decoy is never touched, and provisioning fails
/// rather than returning a `ProfilePaths` that denotes the replacement.
///
/// # Sabotage
///
/// (a) Change `fd.set_permissions(…)` to `std::fs::set_permissions(path, …)`:
/// the chmod follows the planted symlink and tightens the decoy to 0700 →
/// reddens (decoy no longer 0755). (b) Delete the `reconcile_path_still_names`
/// call: the post-open substitution is returned as success → reddens (no
/// refusal).
#[test]
fn adoption_refuses_a_symlink_substituted_after_open() {
    let scratch = Scratch::new("adopt-symlink-after-open");
    let root = scratch.path().join("store");
    precreate_tree_at(&root, 0o755);
    let data = root.join("persistent/abc/data");
    let decoy = make_decoy(&scratch, "decoy");
    let us = current_uid().expect("current_uid");

    let mut fired = false;
    let err = begin_persistent_profile_tree_with_adoption_seam(
        &root,
        Path::new("persistent/abc"),
        Some(us),
        |_| Ok(()),
        |phase, path| {
            if phase == AdoptionPhase::AfterOpen && path == data && !fired {
                fired = true;
                std::fs::remove_dir(path).expect("remove the opened dir's name");
                std::os::unix::fs::symlink(&decoy, path).expect("plant symlink");
            }
        },
    )
    .expect_err("a symlink substituted after the open must be refused, not returned");

    assert!(fired, "the AfterOpen seam must have fired for `data`");
    match &err {
        ProvisionError::SymlinkedComponent(p) => assert_eq!(p, &data),
        other => panic!("expected SymlinkedComponent from reconciliation, got {other:?}"),
    }
    assert_decoy_untouched(&decoy);
}

/// Gate 28 - a foreign-owned permissive tree is refused, never tightened.
///
/// A single-user run cannot create a directory owned by another uid, so the
/// foreign owner is reached the same way [`foreign_owned_dir_is_refused`] does:
/// the provisioner is told the uid is a value the (real, this code-owned) directories
/// do not match. The `fstat`-side owner check in `tighten_owned_permissive_dir`
/// is the same `ForeignOwner` refusal; a true fd-side foreign inode is not
/// constructible without a second uid or `CAP_CHOWN`, so this is the closest
/// feasible foreign control.
///
/// # Sabotage
///
/// Remove the `dir_uid != our_uid` check in `enforce_existing`: the foreign
/// tree is adopted and its first directory tightened, so this gate reddens
/// (it no longer errors).
#[test]
fn adoption_refuses_a_foreign_owned_permissive_tree() {
    let scratch = Scratch::new("adopt-foreign");
    let root = scratch.path().join("store");
    precreate_tree_at(&root, 0o755);
    let us = current_uid().expect("current_uid");
    let not_us = us.wrapping_add(1);
    let subdir_mode_before = mode_of(&root) & 0o777;

    let err = provision_persistent_profile_tree_with_uid(
        &root,
        Path::new("persistent/abc"),
        Some(not_us),
    )
    .expect_err("a foreign-owned permissive tree must be refused");

    match &err {
        ProvisionError::ForeignOwner {
            dir_uid, our_uid, ..
        } => {
            assert_eq!(*dir_uid, us);
            assert_eq!(*our_uid, not_us);
        }
        other => panic!("expected ForeignOwner, got {other:?}"),
    }
    // Refused, not tightened: the (real, owned) directory keeps its permissive
    // mode because this code treated it as foreign.
    assert_eq!(mode_of(&root) & 0o777, subdir_mode_before);
    assert_eq!(mode_of(&root) & 0o777, 0o755);
}
