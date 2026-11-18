//! Kernel and Flatpak metadata checks for a portal-launched renderer.

use super::*;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

const HELPERS: &[&str] = &[
    "usr/local/libexec/wpe-webkit-2.0/WPEWebProcess",
    "usr/libexec/wpe-webkit-2.0/WPEWebProcess",
    "usr/lib/wpe-webkit-2.0/WPEWebProcess",
    "app/libexec/wpe-webkit-2.0/WPEWebProcess",
];

#[cfg(feature = "wpe")]
pub(crate) fn application_id() -> Result<String, String> {
    let document = text("/.flatpak-info")?;
    field(&document, "Application", "name").map(str::to_owned)
}

#[cfg(feature = "wpe")]
pub(crate) fn attest_renderer(pid: u32) -> SandboxAttestation {
    match observe(Path::new("/"), std::process::id(), pid) {
        Ok(verdict) => verdict,
        Err(why) => SandboxAttestation::Unattested(UnattestedReason::FlatpakIsolationFailed {
            pid: Some(pid),
            why,
        }),
    }
}

fn text(path: impl AsRef<Path>) -> Result<String, String> {
    let path = path.as_ref();
    let file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut value = String::new();
    file.take(256 * 1024 + 1)
        .read_to_string(&mut value)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if value.len() > 256 * 1024 {
        return Err("process metadata exceeds its size limit".into());
    }
    Ok(value)
}

fn field<'a>(document: &'a str, section: &str, key: &str) -> Result<&'a str, String> {
    let mut current = "";
    let mut found = None;
    for line in document.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            current = &line[1..line.len() - 1];
        } else if current == section
            && let Some((name, value)) = line.split_once('=')
            && name.trim() == key
        {
            if found.is_some() || value.trim().is_empty() {
                return Err(format!("invalid Flatpak metadata field {section}.{key}"));
            }
            found = Some(value.trim());
        }
    }
    found.ok_or_else(|| format!("missing Flatpak metadata field {section}.{key}"))
}

fn identity(root: &Path, pid: u32) -> Result<Option<ProcessIdentity>, NamespaceReadError> {
    let value = text(root.join(format!("proc/{pid}/stat")))
        .map_err(|why| NamespaceReadError::Unreadable { why })?;
    let entry = parse_stat(&value).ok_or_else(|| NamespaceReadError::Unreadable {
        why: "invalid renderer stat".into(),
    })?;
    if entry.has_exited() {
        return Ok(None);
    }
    Ok(Some(ProcessIdentity {
        pid,
        start_ticks: entry.start_ticks,
    }))
}

fn observe(root: &Path, host_pid: u32, pid: u32) -> Result<SandboxAttestation, String> {
    let host = identity(root, host_pid)
        .map_err(|error| format!("{error:?}"))?
        .ok_or("host process unavailable")?;
    let renderer = identity(root, pid)
        .map_err(|error| format!("{error:?}"))?
        .ok_or("renderer process unavailable")?;
    if renderer == host || text(root.join(format!("proc/{pid}/comm")))?.trim() != "WPEWebProcess" {
        return Err("the native view did not identify a WebProcess".into());
    }
    let executable = fs::metadata(root.join(format!("proc/{pid}/exe")))
        .map_err(|error| format!("renderer executable unavailable: {error}"))?;
    let trusted = HELPERS.iter().any(|path| {
        fs::metadata(root.join(path)).is_ok_and(|expected| {
            expected.is_file()
                && expected.dev() == executable.dev()
                && expected.ino() == executable.ino()
        })
    });
    if !trusted {
        return Err("renderer executable does not match an installed WebKit helper".into());
    }
    let parent_info = text(root.join(".flatpak-info"))?;
    let child_info = text(root.join(format!("proc/{pid}/root/.flatpak-info")))?;
    let app = field(&parent_info, "Application", "name")?;
    if field(&child_info, "Application", "name")? != app {
        return Err("renderer belongs to a different Flatpak application".into());
    }
    for key in ["app-commit", "runtime-commit"] {
        if field(&parent_info, "Instance", key)? != field(&child_info, "Instance", key)? {
            return Err(format!("renderer Flatpak {key} does not match the host"));
        }
    }
    if field(&child_info, "Instance", "sandbox")? != "true"
        || field(&parent_info, "Instance", "instance-id")?
            == field(&child_info, "Instance", "instance-id")?
    {
        return Err("renderer is not a separate Flatpak sandbox instance".into());
    }
    let read_namespace = |pid, kind: &str| {
        fs::read_link(root.join(format!("proc/{pid}/ns/{kind}")))
            .map(|value| value.to_string_lossy().into_owned())
            .map_err(|error| NamespaceReadError::Unreadable {
                why: error.to_string(),
            })
    };
    let read_identity = |pid| identity(root, pid);
    let host_ns = ProcessNamespaces::read_checked_with(host, read_namespace, read_identity)
        .map_err(|error| format!("host namespaces: {error:?}"))?;
    let web_ns = ProcessNamespaces::read_checked_with(renderer, read_namespace, read_identity)
        .map_err(|error| format!("renderer namespaces: {error:?}"))?;
    if host_ns.mnt == web_ns.mnt || host_ns.pid == web_ns.pid {
        return Err("renderer shares the host mount or PID namespace".into());
    }
    let host_net = read_namespace_checked(host, "net", &read_namespace, &read_identity)
        .map_err(|error| format!("host network namespace: {error:?}"))?;
    let web_net = read_namespace_checked(renderer, "net", &read_namespace, &read_identity)
        .map_err(|error| format!("renderer network namespace: {error:?}"))?;
    if host_net == web_net {
        return Err("renderer shares the host network namespace".into());
    }
    let status = text(root.join(format!("proc/{pid}/status")))?;
    for (key, expected) in [("NoNewPrivs", "1"), ("Seccomp", "2")] {
        let values: Vec<_> = status
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| *name == key)
            .map(|(_, value)| value.trim())
            .collect();
        if values != [expected] {
            return Err(format!(
                "renderer {key} does not enforce the sandbox policy"
            ));
        }
    }
    require_same_identity(renderer, read_identity(pid))
        .map_err(|error| format!("renderer identity: {error:?}"))?;
    require_same_identity(host, read_identity(host_pid))
        .map_err(|error| format!("host identity: {error:?}"))?;
    Ok(SandboxAttestation::FlatpakIsolated {
        renderer,
        host: host_ns,
        web: web_ns,
        application_id: app.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "webkit-flatpak-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let this = Self(root);
            for (pid, comm, start) in [(10, "host", 100), (20, "WPEWebProcess", 200)] {
                this.write(&format!("proc/{pid}/stat"), &stat_line(pid, comm, start));
                this.write(&format!("proc/{pid}/comm"), comm);
                for kind in ["mnt", "pid", "user", "net"] {
                    let value = if kind == "user" { 1 } else { pid };
                    this.link(
                        &format!("proc/{pid}/ns/{kind}"),
                        &format!("{kind}:[{value}]"),
                    );
                }
            }
            this.write(HELPERS[0], "trusted helper");
            this.link("proc/20/exe", this.0.join(HELPERS[0]).to_str().unwrap());
            this.write(".flatpak-info", &info("app", "parent", false));
            this.write("proc/20/root/.flatpak-info", &info("app", "child", true));
            this.write("proc/20/status", "NoNewPrivs:\t1\nSeccomp:\t2\n");
            this
        }
        fn write(&self, path: &str, value: &str) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, value).unwrap();
        }
        fn link(&self, path: &str, target: &str) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            if path.is_symlink() {
                fs::remove_file(&path).unwrap();
            }
            symlink(target, path).unwrap();
        }
        fn attest(&self) -> Result<SandboxAttestation, String> {
            observe(&self.0, 10, 20)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn stat_line(pid: u32, comm: &str, start: u64) -> String {
        let mut fields = vec!["0".to_owned(); 40];
        fields[0] = "S".into();
        fields[19] = start.to_string();
        format!("{pid} ({comm}) {}", fields.join(" "))
    }
    fn info(app: &str, instance: &str, sandbox: bool) -> String {
        format!(
            "[Application]\nname={app}\n[Instance]\ninstance-id={instance}\napp-commit=application-deployment\nruntime-commit=runtime-deployment\nsandbox={sandbox}\n"
        )
    }
    #[test]
    fn flatpak_portal_renderer_can_be_attested_without_descendant_ancestry() {
        let f = Fixture::new();
        let verdict = f.attest().unwrap();
        assert!(verdict.is_isolated());
        assert_eq!(
            verdict.subject(),
            Some(ProcessIdentity {
                pid: 20,
                start_ticks: 200
            })
        );
        assert!(
            enforcement_decision_with_outer(
                &verdict,
                OuterSandbox::AcceptedByHost,
                Some(ContainerKind::Flatpak)
            )
            .is_ok()
        );
        assert!(enforcement_decision(&verdict).is_err());
    }
    #[test]
    fn flatpak_renderer_requires_the_installed_helper_inode() {
        let f = Fixture::new();
        f.write("different-helper", "trusted helper");
        f.link(
            "proc/20/exe",
            f.0.join("different-helper").to_str().unwrap(),
        );
        assert!(f.attest().unwrap_err().contains("installed WebKit helper"));
    }
    #[test]
    fn flatpak_renderer_requires_matching_application_and_deployments() {
        let f = Fixture::new();
        for replacement in [
            info("other", "child", true),
            info("app", "child", true).replace("application-deployment", "different-deployment"),
            info("app", "child", true).replace("runtime-deployment", "different-runtime"),
        ] {
            f.write("proc/20/root/.flatpak-info", &replacement);
            assert!(f.attest().is_err());
        }
    }
    #[test]
    fn flatpak_renderer_requires_a_separate_sandbox_instance() {
        let f = Fixture::new();
        for replacement in [info("app", "parent", true), info("app", "child", false)] {
            f.write("proc/20/root/.flatpak-info", &replacement);
            assert!(f.attest().is_err());
        }
    }
    #[test]
    fn flatpak_renderer_requires_mount_pid_and_network_isolation() {
        for kind in ["mnt", "pid", "net"] {
            let f = Fixture::new();
            f.link(&format!("proc/20/ns/{kind}"), &format!("{kind}:[10]"));
            assert!(f.attest().is_err(), "shared {kind} passed");
        }
    }
    #[test]
    fn flatpak_renderer_requires_kernel_privilege_and_syscall_restrictions() {
        for status in [
            "NoNewPrivs: 0\nSeccomp: 2\n",
            "NoNewPrivs: 1\nSeccomp: 0\n",
            "NoNewPrivs: 1\n",
            "NoNewPrivs: 1\nSeccomp: 2\nSeccomp: 0\n",
        ] {
            let f = Fixture::new();
            f.write("proc/20/status", status);
            assert!(f.attest().is_err());
        }
    }
    #[test]
    fn flatpak_renderer_rejects_missing_or_ambiguous_process_metadata() {
        let f = Fixture::new();
        f.write("proc/20/comm", "unrelated");
        assert!(f.attest().is_err());
        f.write("proc/20/comm", "WPEWebProcess");
        f.write(
            "proc/20/root/.flatpak-info",
            &(info("app", "child", true) + "sandbox=true\n"),
        );
        assert!(f.attest().is_err());
        f.write("proc/20/root/.flatpak-info", &info("app", "child", true));
        fs::remove_file(f.0.join("proc/20/ns/net")).unwrap();
        assert!(f.attest().is_err());
    }
    #[test]
    fn flatpak_outer_acceptance_never_excuses_missing_inner_isolation() {
        let verdict = SandboxAttestation::Unattested(UnattestedReason::SharesHostNamespaces {
            pid: 20,
            shared: vec![NamespaceKind::Pid],
        });
        assert!(
            enforcement_decision_with_outer(
                &verdict,
                OuterSandbox::AcceptedByHost,
                Some(ContainerKind::Flatpak)
            )
            .is_err()
        );
    }
}
