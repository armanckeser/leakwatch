use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::sys::{self, Gpu, Memory, ObjType, PoolTag};

pub const SAMPLE_SECS: u64 = 3;
const FINE_KEEP: f64 = 3600.0;
const COARSE_STEP: f64 = 60.0;
const COARSE_KEEP: f64 = 7.0 * 86400.0;
const PROC_COARSE_KEEP: f64 = 86400.0;

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Dev runtimes whose command line is checked for a `\projects\<name>\` path.
const DEV_RUNTIMES: &[&str] = &["node.exe", "bun.exe", "deno.exe", "esbuild.exe", "python.exe", "uv.exe", "cargo.exe"];

#[derive(Clone, Debug)]
pub struct ProcRow {
    pub key: (u32, i64),
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub handles: u32,
    pub private: u64,
    pub threads: u32,
    pub cpu_pct: f64,
    pub age_secs: f64,
    pub session: u32,
    pub process_handles: u32,
    pub thread_handles: u32,
    pub services: Vec<String>,
    pub service_names: Vec<String>,
    /// Every hosted service accepts a stop request (core ones like RpcSs do not).
    pub stoppable: bool,
    pub project: Option<String>,
    pub cmdline: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub t: f64,
    pub uptime: u64,
    pub mem: Memory,
    pub live_processes: u32,
    pub process_objects: u32,
    pub zombies: i64,
    pub zombie_threads: i64,
    pub system_cpu: f64,
    pub procs: Vec<ProcRow>,
    pub pool: Vec<PoolTag>,
    pub gpu: Option<Gpu>,
    pub types: Vec<ObjType>,
}

pub struct Sampler {
    prev_cpu: HashMap<(u32, i64), i64>,
    prev_at: Option<Instant>,
    cmdlines: HashMap<(u32, i64), Option<String>>,
    services: HashMap<u32, Vec<sys::Service>>,
    services_at: Option<Instant>,
    gpu: Option<Gpu>,
    gpu_at: Option<Instant>,
}

impl Sampler {
    pub fn new() -> Self {
        Self {
            prev_cpu: HashMap::new(),
            prev_at: None,
            cmdlines: HashMap::new(),
            services: HashMap::new(),
            services_at: None,
            gpu: None,
            gpu_at: None,
        }
    }

    pub fn sample(&mut self) -> Snapshot {
        let started = Instant::now();
        let elapsed = self.prev_at.map(|p| p.elapsed().as_secs_f64()).unwrap_or(0.0);
        let procs = sys::processes();
        let types = sys::object_types();
        let census = sys::handle_census(&types);
        let mem = sys::memory();

        if self.services_at.is_none_or(|t| t.elapsed().as_secs() >= 30) {
            self.services = sys::services_by_pid();
            self.services_at = Some(Instant::now());
        }
        if self.gpu_at.is_none_or(|t| t.elapsed().as_secs() >= 10) {
            self.gpu = sys::nvidia();
            self.gpu_at = Some(Instant::now());
        }

        let now_ft = filetime_now();
        let live: HashSet<(u32, i64)> = procs.iter().map(|p| (p.pid, p.create_time)).collect();
        self.cmdlines.retain(|k, _| live.contains(k));

        let mut rows = Vec::with_capacity(procs.len());
        let mut cpu_now = HashMap::with_capacity(procs.len());
        let mut system_cpu = 0.0;
        for p in &procs {
            let key = (p.pid, p.create_time);
            let cpu_pct = match (self.prev_cpu.get(&key), elapsed > 0.0) {
                (Some(prev), true) => (p.cpu_100ns - prev) as f64 / 1e7 / elapsed * 100.0,
                _ => 0.0,
            };
            cpu_now.insert(key, p.cpu_100ns);
            if p.pid == 4 {
                system_cpu = cpu_pct;
            }
            let lname = p.name.to_ascii_lowercase();
            let cmdline = if DEV_RUNTIMES.contains(&lname.as_str()) || lname == "cmd.exe" {
                self.cmdlines.entry(key).or_insert_with(|| sys::command_line(p.pid)).clone()
            } else {
                None
            };
            let project = cmdline.as_deref().and_then(project_of);
            rows.push(ProcRow {
                key,
                pid: p.pid,
                ppid: p.ppid,
                name: p.name.clone(),
                handles: p.handles,
                private: p.private,
                threads: p.threads,
                cpu_pct,
                age_secs: if p.create_time > 0 { (now_ft - p.create_time) as f64 / 1e7 } else { 0.0 },
                session: p.session,
                process_handles: census.process_handles.get(&p.pid).copied().unwrap_or(0),
                thread_handles: census.thread_handles.get(&p.pid).copied().unwrap_or(0),
                services: self.services.get(&p.pid).map(|v| v.iter().map(|x| x.name.clone()).collect()).unwrap_or_default(),
                service_names: self.services.get(&p.pid).map(|v| v.iter().map(|x| x.display.clone()).collect()).unwrap_or_default(),
                stoppable: self.services.get(&p.pid).is_some_and(|v| v.iter().all(|x| x.accepts_stop)),
                project,
                cmdline,
            });
        }
        self.prev_cpu = cpu_now;
        self.prev_at = Some(started);

        // Live processes exclude the Idle pseudo-process (pid 0), which has no object.
        let live_processes = procs.iter().filter(|p| p.pid != 0).count() as u32;
        let live_threads: u32 = procs.iter().filter(|p| p.pid != 0).map(|p| p.threads).sum();
        let ty = |n: &str| types.iter().find(|t| t.name == n).map(|t| t.objects).unwrap_or(0);
        let process_objects = ty("Process");
        let thread_objects = ty("Thread");

        Snapshot {
            t: now(),
            uptime: sys::uptime_secs(),
            mem,
            live_processes,
            process_objects,
            zombies: process_objects as i64 - live_processes as i64,
            zombie_threads: thread_objects as i64 - live_threads as i64,
            system_cpu,
            procs: rows,
            pool: sys::pool_tags(),
            gpu: self.gpu,
            types,
        }
    }
}

fn filetime_now() -> i64 {
    // FILETIME epoch is 1601-01-01; Unix epoch is 11644473600 s later.
    ((now() + 11_644_473_600.0) * 1e7) as i64
}

/// Folders that hold installed tools rather than someone's project.
const NOT_PROJECTS: &[&str] = &["\\appdata\\", "\\program files", "\\programdata\\", "\\windows\\", "\\scoop\\", "\\.cargo\\", "\\.rustup\\", "\\.bun\\", "\\.deno\\", "\\.local\\"];

/// The project a dev process belongs to, from its command line:
/// `D:\code\shop\node_modules\.bin\..\vite\bin\vite.js` -> `shop`, `python C:\work\api\main.py` -> `api`.
pub fn project_of(cmd: &str) -> Option<String> {
    let norm = cmd.replace('/', "\\");
    let lower = norm.to_ascii_lowercase();
    let dir = if let Some(i) = lower.find("\\node_modules\\") {
        let start = lower[..i].rfind(['"', ' ']).map(|j| j + 1).unwrap_or(0);
        &norm[start..i]
    } else {
        let script = norm
            .split(|c: char| c == '"' || c.is_whitespace())
            .filter(|t| t.len() > 3 && t.as_bytes().get(1) == Some(&b':'))
            .find(|t| {
                let t = t.to_ascii_lowercase();
                [".js", ".mjs", ".cjs", ".ts", ".mts", ".py"].iter().any(|e| t.ends_with(e))
            })?;
        script.rsplit_once('\\')?.0
    };
    let dir_lower = format!("{}\\", dir.to_ascii_lowercase());
    if NOT_PROJECTS.iter().any(|n| dir_lower.contains(n)) {
        return None;
    }
    let name = dir.trim_end_matches('\\').rsplit('\\').next()?.to_string();
    (!name.is_empty() && !name.ends_with(':')).then_some(name)
}

// ---------------------------------------------------------------- history

#[derive(Default, Clone)]
pub struct Series {
    pub fine: VecDeque<(f64, f64)>,
    pub coarse: VecDeque<(f64, f64)>,
}

impl Series {
    /// Demo only: a straight climb from `from` to `to` over the last `secs`.
    pub fn seed_ramp(&mut self, now: f64, secs: f64, from: f64, to: f64) {
        self.fine.clear();
        self.coarse.clear();
        let n = (secs / COARSE_STEP) as usize;
        for i in 0..=n {
            let t = now - secs + i as f64 * COARSE_STEP;
            let v = from + (to - from) * i as f64 / n as f64;
            self.coarse.push_back((t, v));
            if now - t <= FINE_KEEP {
                self.fine.push_back((t, v));
            }
        }
    }

    pub fn push(&mut self, t: f64, v: f64, coarse_keep: f64) -> bool {
        self.fine.push_back((t, v));
        while self.fine.front().is_some_and(|(ft, _)| t - ft > FINE_KEEP) {
            self.fine.pop_front();
        }
        let add_coarse = self.coarse.back().is_none_or(|(ct, _)| t - ct >= COARSE_STEP);
        if add_coarse {
            self.coarse.push_back((t, v));
            while self.coarse.front().is_some_and(|(ct, _)| t - ct > coarse_keep) {
                self.coarse.pop_front();
            }
        }
        add_coarse
    }

    /// Points inside the window, from the finest series that covers it.
    pub fn window(&self, secs: f64) -> Vec<(f64, f64)> {
        let src = if secs <= FINE_KEEP { &self.fine } else { &self.coarse };
        let end = src.back().map(|p| p.0).unwrap_or(0.0);
        src.iter().filter(|p| end - p.0 <= secs).copied().collect()
    }
}

/// Least-squares slope in units per hour, plus how many seconds of data it covers.
pub fn slope_per_hour(pts: &[(f64, f64)]) -> (f64, f64) {
    if pts.len() < 3 {
        return (0.0, 0.0);
    }
    let n = pts.len() as f64;
    let t0 = pts[0].0;
    let (mut sx, mut sy, mut sxx, mut sxy) = (0.0, 0.0, 0.0, 0.0);
    for &(t, v) in pts {
        let x = t - t0;
        sx += x;
        sy += v;
        sxx += x * x;
        sxy += x * v;
    }
    let d = n * sxx - sx * sx;
    if d.abs() < f64::EPSILON {
        return (0.0, 0.0);
    }
    ((n * sxy - sx * sy) / d * 3600.0, pts.last().unwrap().0 - t0)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Metric {
    Zombies,
    ZombieThreads,
    Handles,
    Commit,
    Nonpaged,
    Paged,
    SystemCpu,
    GpuMem,
    Available,
}

impl Metric {
    pub const ALL: [Metric; 9] = [
        Metric::Zombies,
        Metric::ZombieThreads,
        Metric::Handles,
        Metric::Commit,
        Metric::Available,
        Metric::Nonpaged,
        Metric::Paged,
        Metric::SystemCpu,
        Metric::GpuMem,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Metric::Zombies => "Zombie processes",
            Metric::ZombieThreads => "Zombie threads",
            Metric::Handles => "Open handles",
            Metric::Commit => "Committed memory",
            Metric::Available => "Free RAM",
            Metric::Nonpaged => "Nonpaged pool",
            Metric::Paged => "Paged pool",
            Metric::SystemCpu => "Kernel (System) CPU",
            Metric::GpuMem => "GPU memory",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Metric::Zombies => "Exited processes kept alive by an open handle. A few hundred is normal.",
            Metric::ZombieThreads => "Exited threads kept alive by an open handle.",
            Metric::Handles => "Handles open across every process.",
            Metric::Commit => "Memory promised to processes and the kernel, out of the commit limit.",
            Metric::Available => "Physical memory not in use.",
            Metric::Nonpaged => "Kernel memory that never goes to disk. Grows when a driver leaks.",
            Metric::Paged => "Kernel memory that can go to disk.",
            Metric::SystemCpu => "CPU used by the System process, in percent of one core.",
            Metric::GpuMem => "Dedicated GPU memory in use.",
        }
    }

    pub fn csv(self) -> &'static str {
        match self {
            Metric::Zombies => "zombies",
            Metric::ZombieThreads => "zombie_threads",
            Metric::Handles => "handles",
            Metric::Commit => "commit",
            Metric::Available => "available",
            Metric::Nonpaged => "nonpaged",
            Metric::Paged => "paged",
            Metric::SystemCpu => "system_cpu",
            Metric::GpuMem => "gpu_mem",
        }
    }

    pub fn is_bytes(self) -> bool {
        matches!(self, Metric::Commit | Metric::Nonpaged | Metric::Paged | Metric::GpuMem | Metric::Available)
    }

    pub fn value(self, s: &Snapshot) -> Option<f64> {
        Some(match self {
            Metric::Zombies => s.zombies as f64,
            Metric::ZombieThreads => s.zombie_threads as f64,
            Metric::Handles => s.mem.handles as f64,
            Metric::Commit => s.mem.commit as f64,
            Metric::Available => s.mem.available as f64,
            Metric::Nonpaged => s.mem.nonpaged as f64,
            Metric::Paged => s.mem.paged as f64,
            Metric::SystemCpu => s.system_cpu,
            Metric::GpuMem => s.gpu?.mem_used_mb * 1048576.0,
        })
    }

    /// Value above which the row is a problem regardless of trend.
    pub fn limit(self, s: &Snapshot) -> Option<f64> {
        match self {
            Metric::Zombies => Some(2000.0),
            Metric::ZombieThreads => Some(10000.0),
            Metric::Commit => Some(s.mem.commit_limit as f64 * 0.9),
            Metric::Nonpaged => Some(2.0 * 1024.0 * 1024.0 * 1024.0),
            Metric::SystemCpu => Some(60.0),
            _ => None,
        }
    }

    /// Growth per hour that counts as a leak when sustained.
    pub fn growth_alarm(self) -> Option<f64> {
        match self {
            Metric::Zombies => Some(100.0),
            Metric::ZombieThreads => Some(500.0),
            Metric::Handles => Some(5000.0),
            Metric::Commit => Some(1024.0 * 1024.0 * 1024.0),
            Metric::Nonpaged => Some(100.0 * 1024.0 * 1024.0),
            Metric::Paged => Some(200.0 * 1024.0 * 1024.0),
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct ProcHist {
    pub handles: Series,
    pub private: Series,
    pub last_seen: f64,
}

pub struct History {
    pub system: HashMap<Metric, Series>,
    pub procs: HashMap<(u32, i64), ProcHist>,
    pub pool: HashMap<String, Series>,
    pub types: HashMap<String, Series>,
    /// Off in demo mode, so made-up numbers never reach system.csv.
    pub persist: bool,
    log: Option<std::fs::File>,
}

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("leakwatch")
}

impl History {
    pub fn load() -> Self {
        let dir = data_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("system.csv");
        let mut system: HashMap<Metric, Series> = HashMap::new();
        let cutoff = now() - COARSE_KEEP;
        if let Ok(f) = std::fs::File::open(&path) {
            let mut lines = std::io::BufReader::new(f).lines();
            let header: Vec<String> = lines
                .next()
                .and_then(|l| l.ok())
                .map(|l| l.split(',').map(str::to_string).collect())
                .unwrap_or_default();
            for line in lines.map_while(Result::ok) {
                let cols: Vec<&str> = line.split(',').collect();
                let Some(t) = cols.first().and_then(|c| c.parse::<f64>().ok()) else { continue };
                if t < cutoff {
                    continue;
                }
                for m in Metric::ALL {
                    let Some(i) = header.iter().position(|h| h == m.csv()) else { continue };
                    if let Some(v) = cols.get(i).and_then(|c| c.parse::<f64>().ok()) {
                        system.entry(m).or_default().coarse.push_back((t, v));
                    }
                }
            }
        }
        let fresh = !path.exists();
        let mut log = std::fs::OpenOptions::new().create(true).append(true).open(&path).ok();
        if fresh {
            if let Some(f) = log.as_mut() {
                let cols: Vec<&str> = Metric::ALL.iter().map(|m| m.csv()).collect();
                let _ = writeln!(f, "t,{}", cols.join(","));
            }
        }
        Self { system, procs: HashMap::new(), pool: HashMap::new(), types: HashMap::new(), persist: true, log }
    }

    pub fn record(&mut self, s: &Snapshot) {
        let mut wrote_coarse = false;
        for m in Metric::ALL {
            let v = m.value(s).unwrap_or(f64::NAN);
            if v.is_nan() {
                continue;
            }
            wrote_coarse |= self.system.entry(m).or_default().push(s.t, v, COARSE_KEEP);
        }
        if wrote_coarse && self.persist {
            if let Some(f) = self.log.as_mut() {
                let vals: Vec<String> = Metric::ALL
                    .iter()
                    .map(|m| m.value(s).map(|v| format!("{v:.0}")).unwrap_or_default())
                    .collect();
                let _ = writeln!(f, "{:.0},{}", s.t, vals.join(","));
            }
        }
        for p in &s.procs {
            let h = self.procs.entry(p.key).or_default();
            h.handles.push(s.t, p.handles as f64, PROC_COARSE_KEEP);
            h.private.push(s.t, p.private as f64, PROC_COARSE_KEEP);
            h.last_seen = s.t;
        }
        self.procs.retain(|_, h| s.t - h.last_seen < 30.0);
        for tag in &s.pool {
            let total = (tag.nonpaged + tag.paged) as f64;
            if total >= 1024.0 * 1024.0 || self.pool.contains_key(&tag.tag) {
                self.pool.entry(tag.tag.clone()).or_default().push(s.t, total, COARSE_KEEP);
            }
        }
        for ty in &s.types {
            self.types.entry(ty.name.clone()).or_default().push(s.t, ty.objects as f64, COARSE_KEEP);
        }
    }
}

// ---------------------------------------------------------------- formatting

pub fn fmt_bytes(b: f64) -> String {
    let a = b.abs();
    if a >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} GB", b / 1073741824.0)
    } else if a >= 1024.0 * 1024.0 {
        format!("{:.0} MB", b / 1048576.0)
    } else if a >= 1024.0 {
        format!("{:.0} KB", b / 1024.0)
    } else {
        format!("{b:.0} B")
    }
}

pub fn fmt_count(v: f64) -> String {
    let n = v.round() as i64;
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 { format!("-{out}") } else { out }
}

pub fn fmt_age(secs: f64) -> String {
    if secs >= 86400.0 {
        format!("{:.1} d", secs / 86400.0)
    } else if secs >= 3600.0 {
        format!("{:.1} h", secs / 3600.0)
    } else if secs >= 60.0 {
        format!("{:.0} min", secs / 60.0)
    } else {
        format!("{secs:.0} s")
    }
}
