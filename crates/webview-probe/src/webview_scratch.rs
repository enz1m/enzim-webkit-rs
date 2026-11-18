//! Secure scratch for the probe's native WPE page.
//!
//! Never `temp_dir().join(format!("enzui-probe-web-{pid}"))`: a predictable name under
//! the world-writable tmpfs, where any uid could pre-plant a symlink, directory, or
//! bind mount under a future cookie jar. This module composes on
//! [`enzui_core::runtime_dir`]: an owner-only `$XDG_RUNTIME_DIR` when valid, or a
//! verified 0700 `/tmp/enzui-<uid>/` fallback.
//!
//! Cross-uid protection: the container sits inside the validated owner-only runtime dir
//! (inherited guarantee); the 0700 leaf is created exclusively, so a pre-existing final
//! component - dir, file, or symlink - returns `EEXIST` and is never adopted; perms are
//! set 0700 after `mkdir`; the native worker holds a shared lease, dropped before the
//! service's final lease on prompt shutdown, retained across a bounded-join timeout.
//! Same-uid processes are not a boundary: exclusive creation refuses adoption but
//! cannot stop later same-uid renames or races.
//! Crashes skip `Drop`, and sibling PID sweep is refused: reuse, namespaces, and live
//! WPE children make that deletion unsafe. Residue is never adopted - the timestamped
//! leaf routes later runs elsewhere; session managers clean the runtime dir.

use std::path::Path;

use enzui_core::runtime_dir::{RuntimeDir, RuntimeDirOrigin, runtime_dir};
use enzui_core::secure_dir::SecureRoot;
use enzui_core::tempstage::DirectoryStage;

/// A 0700 scratch directory owned by this process, with Drop cleanup. Construct via
/// [`SecureScratch::open_for_native_webview`].
#[derive(Debug)]
pub struct SecureScratch {
    stage: DirectoryStage,
    /// Refusal-vs-absence origin: a set-but-unsafe `$XDG_RUNTIME_DIR` surfaces in the
    /// status line; a benign absence stays quiet.
    origin: RuntimeDirOrigin,
}

impl SecureScratch {
    #[must_use]
    pub fn path(&self) -> &Path {
        self.stage.path()
    }

    /// On-screen note for a set-but-unsafe `$XDG_RUNTIME_DIR`; `None` otherwise.
    #[must_use]
    pub fn refusal_note(&self) -> Option<String> {
        match &self.origin {
            RuntimeDirOrigin::Fallback(reason) if reason.is_refusal() => Some(format!(
                "runtime dir REFUSED $XDG_RUNTIME_DIR ({reason}); using {}",
                self.stage.path().display()
            )),
            _ => None,
        }
    }

    /// Terminal states: no secure runtime dir at all, or a refused exclusive leaf
    /// create the caller must not adopt.
    pub fn open_for_native_webview() -> Result<Self, String> {
        let dir = runtime_dir().map_err(|e| format!("runtime dir unavailable: {e}"))?;
        Self::open_under_root(&dir, "probe-webview")
    }

    /// Fresh `<pid>-<start-nanos>-<seq>` leaf under `<runtime>/<tag>/`.
    pub(crate) fn open_under_root(dir: &RuntimeDir, tag: &str) -> Result<Self, String> {
        let root = dir.join(tag);
        // Lazily created: a probeless run leaves no path on disk.
        create_dir_0700(&root).map_err(|e| format!("secure_temp: {}: {e}", root.display()))?;
        // No PID-sibling sweep: PIDs are not process identities across reuse or
        // namespaces, and a WPE child may still be exiting.
        let parent =
            SecureRoot::open(&root).map_err(|e| format!("secure_temp: {}: {e}", root.display()))?;
        let name = unique_suffix();
        let stage = DirectoryStage::create(&parent, std::ffi::OsStr::new(&name))
            .map_err(|e| format!("secure_temp: {}: {e}", root.join(name).display()))?;
        Ok(Self {
            stage,
            origin: dir.origin().clone(),
        })
    }
}

/// Uniqueness suffix, not a secret: the timestamp keeps a `<pid>-0` crash residue from
/// blocking a later pid-reuser; a same-uid process can still predict candidates (DoS).
fn unique_suffix() -> String {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    static START_NANOS: OnceLock<u128> = OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let start_nanos = START_NANOS.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    });
    format!(
        "{}-{start_nanos}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// 0700 directory, adopting an existing one only if already 0700 and owned by the current user.
#[cfg(unix)]
fn create_dir_0700(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(path)?;
            if !meta.file_type().is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} exists but is not a directory", path.display()),
                ));
            }
            let uid = enzui_core::runtime_dir::current_uid();
            if let Some(uid) = uid
                && meta.uid() != uid
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "{} exists but is owned by uid {} not our uid {}",
                        path.display(),
                        meta.uid(),
                        uid
                    ),
                ));
            }
            let mode = meta.mode() & 0o7777;
            if mode & 0o077 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} has unsafe mode {mode:o}", path.display()),
                ));
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn create_dir_0700(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Per-invocation unique root beside the test binary; parallel-safe.
    fn scratch_root(tag: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::current_exe()
            .expect("current_exe")
            .parent()
            .expect("binary directory")
            .join(format!(
                "webview-scratch-secure-{tag}-{}-{}-{n}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
        std::fs::create_dir_all(&dir).expect("mkdir root");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod root");
        dir
    }

    // Owner read independently from `current_uid`.
    fn uid() -> u32 {
        std::fs::metadata(std::env::current_exe().expect("current_exe"))
            .expect("stat test executable")
            .uid()
    }

    #[test]
    fn secure_scratch_drop_preserves_a_nonempty_replacement() {
        use std::sync::mpsc;
        use std::time::Duration;

        let base = scratch_root("drop-substitution");
        let dir = enzui_core::runtime_dir::resolve(None, Some(uid()), &base)
            .expect("resolve fallback runtime dir");
        let scratch =
            SecureScratch::open_under_root(&dir, "probe-webview").expect("secure scratch open");
        let leaf = scratch.path().to_path_buf();
        let displaced = leaf.with_extension("displaced-owned");
        let original_identity = scratch.stage.root().identity();
        let (start_tx, start_rx) = mpsc::sync_channel(0);
        let (done_tx, done_rx) = mpsc::sync_channel(0);
        let actor_leaf = leaf.clone();
        let actor = std::thread::spawn(move || {
            start_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("scratch Drop did not reach the substitution seam");
            std::fs::rename(&actor_leaf, &displaced).expect("displace owned scratch");
            std::fs::create_dir(&actor_leaf).expect("create replacement scratch");
            std::fs::create_dir(actor_leaf.join("foreign")).expect("create replacement descendant");
            std::fs::write(actor_leaf.join("foreign/marker"), b"foreign")
                .expect("write replacement descendant");
            done_tx.send(()).expect("report completed substitution");
        });
        enzui_core::tempstage::fault::arm_directory_cleanup(
            leaf.clone(),
            Box::new(move |_| {
                start_tx.send(()).expect("wake substitution actor");
                done_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("substitution actor did not finish");
            }),
        );

        drop(scratch);
        actor.join().expect("substitution actor");
        assert!(
            !enzui_core::tempstage::fault::is_armed(),
            "the SecureScratch Drop seam was not consumed"
        );
        let replacement = std::fs::symlink_metadata(&leaf).expect("replacement survived");
        assert_ne!((replacement.dev(), replacement.ino()), original_identity);
        assert_eq!(
            std::fs::read(leaf.join("foreign/marker")).expect("read foreign descendant"),
            b"foreign"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `mkdir` does not follow the final component, so the leaf create returns `EEXIST`.
    /// A following implementation would leave evidence in the target; the test proves it
    /// unchanged.
    #[test]
    fn refuses_a_pre_existing_symlink_at_the_leaf() {
        use std::os::unix::fs::symlink;
        let root = scratch_root("hostile-symlink");
        let target = root.join("target");
        std::fs::create_dir(&target).expect("mkdir target");
        let sentinel = target.join("sentinel");
        std::fs::write(&sentinel, b"do-not-touch").expect("seed sentinel");
        let target_before = std::fs::metadata(&target).expect("stat target").mtime();

        let leaf = root.join("leaf");
        symlink(&target, &leaf).expect("plant hostile symlink");
        let parent = SecureRoot::open(&root).expect("open test parent");
        let err = DirectoryStage::create(&parent, std::ffi::OsStr::new("leaf"))
            .expect_err("a pre-existing symlink at the leaf must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

        // Target untouched: nothing added, sentinel intact, mtime equal.
        assert!(
            sentinel.exists(),
            "the sentinel behind the symlink must be untouched"
        );
        assert_eq!(
            std::fs::read(&sentinel).expect("read sentinel"),
            b"do-not-touch",
            "symlink-target contents must be unchanged",
        );
        let target_after = std::fs::metadata(&target).expect("stat target").mtime();
        assert_eq!(
            target_before, target_after,
            "symlink-target directory mtime must be unchanged (nothing added inside)",
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
