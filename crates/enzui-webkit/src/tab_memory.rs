//! Keeping a browser's memory in bounds as its tabs pile up, as Chromium's
//! memory reducer and tab discarding do: hidden tabs release memory on a
//! schedule, and when the system runs short of memory the least recently used
//! background tab is discarded, its process closed until it is shown again.
//!
//! The browser calls [`TabMemoryPolicy::tick`] about once a second with the
//! state of its tabs and the current [`MemoryPressure`], and carries out the
//! returned actions: [`TabAction::Release`] with `WebSession::release_memory`
//! and [`TabAction::Discard`] with `WebSession::discard`. Nothing here needs
//! the native runtime.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// How short of memory the system or the browser's cgroup is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryPressure {
    /// Enough memory is available.
    Normal,
    /// Memory is getting short: background tabs not used for a while go.
    Moderate,
    /// Memory is nearly gone: a background tab goes at every tick until the
    /// pressure eases, before the kernel kills a process.
    Critical,
}

/// When available memory counts as short, as a share of the memory the
/// browser may use: the system's, or its cgroup limit when lower.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PressureThresholds {
    /// Below this share of the total, pressure is moderate.
    pub moderate_fraction: f64,
    /// Below this share of the total, pressure is critical.
    pub critical_fraction: f64,
    /// A share of the last ten seconds in which every task waited for memory
    /// (`full avg10` of the kernel's pressure stall information), in percent,
    /// from which pressure is critical whatever is available.
    pub critical_stall_percent: f64,
}

impl Default for PressureThresholds {
    fn default() -> Self {
        Self {
            moderate_fraction: 0.15,
            critical_fraction: 0.07,
            critical_stall_percent: 10.0,
        }
    }
}

/// The memory the browser may use and how much of it is available.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemorySnapshot {
    /// The system's memory, or the cgroup limit when lower.
    pub total_bytes: u64,
    /// Estimated memory available without swapping, bounded by readable cgroup
    /// ancestors. Clean inactive file cache can be reclaimed; dirty/writeback
    /// data is retained in the working-set estimate.
    pub available_bytes: u64,
    /// The largest known system/cgroup `full avg10` memory stall percentage.
    pub stall_percent: Option<f64>,
}

impl MemorySnapshot {
    /// Reads `/proc/meminfo`, this process's cgroup limit and usage, and
    /// `/proc/pressure/memory`.
    ///
    /// # Errors
    /// When `/proc/meminfo` cannot be read or lacks `MemTotal` and
    /// `MemAvailable`.
    pub fn read() -> std::io::Result<Self> {
        let meminfo = std::fs::read_to_string("/proc/meminfo")?;
        let (total, available) = parse_meminfo(&meminfo).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no MemTotal or MemAvailable",
            )
        })?;
        let cgroup = std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|text| cgroup_memory(&text));
        let stall = std::fs::read_to_string("/proc/pressure/memory")
            .ok()
            .and_then(|text| parse_full_stall(&text));
        Ok(Self::combine(total, available, cgroup, stall))
    }

    fn combine(
        total: u64,
        available: u64,
        cgroup: Option<CgroupMemory>,
        stall: Option<f64>,
    ) -> Self {
        let (total_bytes, available_bytes, stall_percent) = match cgroup {
            Some(group) => (
                total.min(group.limit),
                available.min(group.available),
                match (stall, group.stall_percent) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                },
            ),
            None => (total, available, stall),
        };
        Self {
            total_bytes,
            available_bytes: available_bytes.min(total_bytes),
            stall_percent,
        }
    }

    /// The pressure these numbers mean under the thresholds.
    #[must_use]
    pub fn pressure(&self, thresholds: &PressureThresholds) -> MemoryPressure {
        let total = self.total_bytes as f64;
        let available = self.available_bytes as f64;
        if self.total_bytes == 0
            || available < total * thresholds.critical_fraction
            || self
                .stall_percent
                .is_some_and(|stall| stall >= thresholds.critical_stall_percent)
        {
            MemoryPressure::Critical
        } else if available < total * thresholds.moderate_fraction {
            MemoryPressure::Moderate
        } else {
            MemoryPressure::Normal
        }
    }
}

fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|kib| kib.parse::<u64>().ok())
            .and_then(|kib| kib.checked_mul(1024))
    };
    Some((field("MemTotal:")?, field("MemAvailable:")?))
}

#[derive(Debug, Clone, Copy)]
struct CgroupMemory {
    limit: u64,
    available: u64,
    stall_percent: Option<f64>,
}

fn cgroup_memory(proc_cgroup: &str) -> Option<CgroupMemory> {
    cgroup_memory_at(
        std::path::Path::new("/sys/fs/cgroup"),
        proc_cgroup,
        |path| std::fs::read_to_string(path).ok(),
    )
}

fn cgroup_memory_at(
    root: &std::path::Path,
    proc_cgroup: &str,
    read: impl Fn(&std::path::Path) -> Option<String>,
) -> Option<CgroupMemory> {
    use std::path::Component;
    let path = proc_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?;
    let mut components = std::path::Path::new(path).components();
    if components.next() != Some(Component::RootDir) {
        return None;
    }
    if components
        .clone()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    let mut components = components.peekable();
    let mut directory = root.to_owned();
    let mut result = CgroupMemory {
        limit: u64::MAX,
        available: u64::MAX,
        stall_percent: None,
    };
    let mut found = false;
    loop {
        let limit = read(&directory.join("memory.max")).and_then(|s| s.trim().parse::<u64>().ok());
        if (limit.is_some() || components.peek().is_none())
            && let Some(stall) =
                read(&directory.join("memory.pressure")).and_then(|s| parse_full_stall(&s))
        {
            result.stall_percent =
                Some(result.stall_percent.map_or(stall, |prior| prior.max(stall)));
            found = true;
        }
        if let Some(limit) = limit
            && let Some(usage) =
                read(&directory.join("memory.current")).and_then(|s| s.trim().parse::<u64>().ok())
        {
            let reclaimable = read(&directory.join("memory.stat"))
                .and_then(|s| reclaimable_file_cache(&s))
                .unwrap_or(0)
                .min(usage);
            result.limit = result.limit.min(limit);
            result.available = result
                .available
                .min(limit.saturating_sub(usage.saturating_sub(reclaimable)));
            found = true;
        }
        match components.next() {
            Some(component) => directory.push(component.as_os_str()),
            None => break,
        }
    }
    found.then_some(result)
}

fn reclaimable_file_cache(stat: &str) -> Option<u64> {
    let mut inactive = None;
    let mut dirty = None;
    let mut writeback = None;
    for line in stat.lines() {
        let mut fields = line.split_whitespace();
        let target = match fields.next()? {
            "inactive_file" => &mut inactive,
            "file_dirty" => &mut dirty,
            "file_writeback" => &mut writeback,
            _ => continue,
        };
        let value = fields.next()?.parse::<u64>().ok()?;
        if fields.next().is_some() || target.replace(value).is_some() {
            return None;
        }
    }
    Some(inactive?.saturating_sub(dirty?.saturating_add(writeback?)))
}

fn parse_full_stall(text: &str) -> Option<f64> {
    text.lines()
        .find_map(|line| line.strip_prefix("full "))?
        .split_whitespace()
        .find_map(|field| field.strip_prefix("avg10="))?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && (0.0..=100.0).contains(value))
}

/// A tab as the policy sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabState<K> {
    /// The browser's identifier for the tab.
    pub key: K,
    /// Whether the tab is on screen.
    pub visible: bool,
    /// When the tab was last on screen; now for a visible tab.
    pub last_visible: Instant,
    /// A tab playing audio is never discarded.
    pub playing_audio: bool,
    /// A tab the browser keeps, such as one with unsent form input or one the
    /// user pinned, is never discarded.
    pub protected: bool,
    /// The tab is discarded already.
    pub discarded: bool,
}

/// What the browser does with a tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TabAction<K> {
    /// Release the tab's memory (`WebSession::release_memory`).
    Release(K),
    /// Discard the tab (`WebSession::discard`) and restore it when shown.
    Discard(K),
}

/// When hidden tabs release memory and are discarded.
#[derive(Debug, Clone)]
pub struct TabMemoryPolicy<K> {
    /// How long after hiding a tab releases memory, in turn; a release follows
    /// a tab's first hour of use more often than later ones.
    pub release_after: Vec<Duration>,
    /// After the scheduled releases, how often a hidden tab releases again.
    pub release_every: Duration,
    /// Under moderate pressure, how long a tab must have been hidden before it
    /// is discarded; under critical pressure it goes at once.
    pub moderate_discard_after: Duration,
    /// Discard tabs hidden this long even without pressure, as Chromium's
    /// Memory Saver does; `None` keeps them.
    pub discard_after: Option<Duration>,
    releases: HashMap<K, Releases>,
}

#[derive(Debug, Clone, Copy)]
struct Releases {
    hidden_since: Instant,
    count: usize,
    last: Option<Instant>,
}

impl<K> Default for TabMemoryPolicy<K> {
    fn default() -> Self {
        Self {
            release_after: vec![Duration::from_secs(30), Duration::from_secs(5 * 60)],
            release_every: Duration::from_secs(30 * 60),
            moderate_discard_after: Duration::from_secs(10 * 60),
            discard_after: None,
            releases: HashMap::new(),
        }
    }
}

impl<K: Clone + Eq + Hash> TabMemoryPolicy<K> {
    /// The actions due now: releases for hidden tabs on their schedule, and
    /// discards the pressure or [`Self::discard_after`] call for. At most one
    /// tab is discarded per tick for pressure, so the browser can read the
    /// pressure again before discarding another.
    pub fn tick(
        &mut self,
        now: Instant,
        pressure: MemoryPressure,
        tabs: &[TabState<K>],
    ) -> Vec<TabAction<K>> {
        let mut actions = Vec::new();
        let candidates = || {
            tabs.iter().filter(|tab| {
                !tab.visible && !tab.discarded && !tab.playing_audio && !tab.protected
            })
        };
        let hidden_for = |tab: &TabState<K>| now.saturating_duration_since(tab.last_visible);

        let pressure_discard = match pressure {
            MemoryPressure::Critical => candidates().min_by_key(|tab| tab.last_visible),
            MemoryPressure::Moderate => candidates()
                .filter(|tab| hidden_for(tab) >= self.moderate_discard_after)
                .min_by_key(|tab| tab.last_visible),
            MemoryPressure::Normal => None,
        };
        if let Some(tab) = pressure_discard {
            actions.push(TabAction::Discard(tab.key.clone()));
        }
        if let Some(after) = self.discard_after {
            for tab in candidates() {
                if hidden_for(tab) >= after
                    && !actions.contains(&TabAction::Discard(tab.key.clone()))
                {
                    actions.push(TabAction::Discard(tab.key.clone()));
                }
            }
        }

        self.releases.retain(|key, _| {
            tabs.iter()
                .any(|tab| &tab.key == key && !tab.visible && !tab.discarded)
        });
        for tab in tabs {
            if tab.visible
                || tab.discarded
                || actions.contains(&TabAction::Discard(tab.key.clone()))
            {
                continue;
            }
            let releases = self.releases.entry(tab.key.clone()).or_insert(Releases {
                hidden_since: tab.last_visible,
                count: 0,
                last: None,
            });
            let due = match self.release_after.get(releases.count) {
                Some(after) => releases.hidden_since + *after,
                None => releases.last.unwrap_or(releases.hidden_since) + self.release_every,
            };
            if now >= due {
                releases.count += 1;
                releases.last = Some(now);
                actions.push(TabAction::Release(tab.key.clone()));
            }
        }
        actions
    }
}
