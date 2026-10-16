#![windows_subsystem = "windows"]

mod findings;
mod model;
mod status;
mod sys;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gpui::{
    App, Application, Bounds, ClickEvent, Context, Div, PathBuilder, Rgba, SharedString,
    Stateful, Window, WindowBounds, WindowOptions, canvas, div, point, prelude::*, px, size,
};

use model::{
    History, Metric, ProcRow, Snapshot, fmt_age, fmt_bytes, fmt_count, slope_per_hour,
};

// One rule: a row stays grey until it grows. Amber = rising past its leak rate, red = past its limit.
// Same palette as the status page (status.rs), as RRGGBBAA over the acrylic window.
const BG: u32 = 0x00000000;
const PANEL: u32 = status::SURFACE;
const LINE: u32 = status::STROKE;
const TEXT: u32 = status::TEXT_1;
const MUTED: u32 = status::TEXT_2;
const FAINT: u32 = status::TEXT_3;
const AMBER: u32 = status::CAUTION;
const RED: u32 = status::CRITICAL;
const MONO: &str = "Cascadia Mono";

#[derive(Clone, Copy, PartialEq)]
enum Span {
    H1,
    H6,
    D1,
    D7,
}

impl Span {
    fn secs(self) -> f64 {
        match self {
            Span::H1 => 3600.0,
            Span::H6 => 6.0 * 3600.0,
            Span::D1 => 86400.0,
            Span::D7 => 7.0 * 86400.0,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Span::H1 => "1 h",
            Span::H6 => "6 h",
            Span::D1 => "24 h",
            Span::D7 => "7 d",
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Status,
    Details,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Growing,
    Holders,
    Handles,
    Memory,
}

#[derive(Clone, Copy, PartialEq)]
enum Level {
    Quiet,
    Growing,
    Over,
}

impl Level {
    fn color(self) -> u32 {
        match self {
            Level::Quiet => TEXT,
            Level::Growing => AMBER,
            Level::Over => RED,
        }
    }
}

struct Action {
    label: String,
    admin: bool,
    command: String,
}

struct Acted {
    at: f64,
    label: String,
    metric: Metric,
    before: f64,
}

struct Leakwatch {
    latest: Option<Snapshot>,
    history: History,
    span: Span,
    tab: Tab,
    confirm: Option<(String, Instant)>,
    status: Option<(String, Instant)>,
    alerted: HashMap<String, f64>,
    actions: Vec<Action>,
    ignored: HashSet<String>,
    acted: HashMap<String, Acted>,
    /// Pool tag -> driver files containing it; None while the scan runs.
    tag_drivers: Arc<Mutex<HashMap<String, Option<Vec<String>>>>>,
    /// LEAKWATCH_DEMO=1 injects a zombie-holding service so the findings view can be seen and filmed.
    demo: Option<bool>,
    page: Page,
    scripts_open: bool,
    /// Which finding is shown large when there are several.
    focus: Option<String>,
    /// Hold-to-confirm in progress: button key and when the press started.
    hold: Option<(String, Instant)>,
    hold_target: Option<(String, Metric, findings::Act)>,
    /// A hold released too early: show "Hold" on that button briefly.
    hold_hint: Option<(String, Instant)>,
    /// Last size the window was fitted to, so resizing happens once per change.
    fitted: Option<(i32, i32)>,
}

impl Leakwatch {
    fn new(actions: Vec<Action>) -> Self {
        Self {
            latest: None,
            history: History::load(),
            span: Span::H1,
            tab: Tab::Growing,
            confirm: None,
            status: None,
            alerted: HashMap::new(),
            actions,
            ignored: read_lines("ignored.txt").into_iter().collect(),
            acted: load_acted(),
            tag_drivers: Arc::new(Mutex::new(HashMap::new())),
            demo: std::env::var("LEAKWATCH_DEMO").is_ok().then_some(false),
            page: Page::Status,
            scripts_open: false,
            focus: None,
            hold: None,
            hold_target: None,
            hold_hint: None,
            fitted: None,
        }
    }
}

fn read_lines(file: &str) -> Vec<String> {
    std::fs::read_to_string(model::data_dir().join(file))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

fn load_acted() -> HashMap<String, Acted> {
    read_lines("acted.txt")
        .into_iter()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let key = f.next()?.to_string();
            let at = f.next()?.parse().ok()?;
            let metric = Metric::ALL.into_iter().find(|m| Some(m.csv()) == f.clone().next())?;
            f.next();
            let before = f.next()?.parse().ok()?;
            let label = f.next().unwrap_or("").to_string();
            Some((key, Acted { at, label, metric, before }))
        })
        .collect()
}

fn main() {
    // `leakwatch --report <file>`: take two samples and write the text report, no window.
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--report") {
        sys::attach_parent_console();
        let mut sampler = model::Sampler::new();
        let mut view = Leakwatch::new(vec![]);
        for n in 0..2 {
            if n > 0 {
                std::thread::sleep(Duration::from_secs(model::SAMPLE_SECS));
            }
            let s = sampler.sample();
            view.history.record(&s);
            view.latest = Some(s);
        }
        let out = view.report();
        match args.get(i + 1) {
            Some(path) => std::fs::write(path, out).expect("write report"),
            None => print!("{out}"),
        }
        return;
    }

    let shared: Arc<Mutex<Option<Snapshot>>> = Arc::new(Mutex::new(None));
    {
        let shared = shared.clone();
        std::thread::spawn(move || {
            let mut sampler = model::Sampler::new();
            loop {
                let snap = sampler.sample();
                *shared.lock().unwrap() = Some(snap);
                std::thread::sleep(Duration::from_secs(model::SAMPLE_SECS));
            }
        });
    }

    Application::new().run(move |cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(status::STATUS_WIDTH), px(360.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_background: gpui::WindowBackgroundAppearance::Blurred,
                window_min_size: Some(size(px(420.), px(160.))),
                titlebar: Some(gpui::TitlebarOptions {
                    title: Some("leakwatch".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            move |_, cx| {
                cx.new(|cx| {
                    let shared = shared.clone();
                    cx.spawn(async move |this, cx| {
                        loop {
                            cx.background_executor().timer(Duration::from_millis(500)).await;
                            let snap = shared.lock().unwrap().take();
                            let alive = this.update(cx, |view: &mut Leakwatch, cx| {
                                if let Some(s) = snap {
                                    view.ingest(s);
                                    cx.notify();
                                } else if view.confirm.as_ref().is_some_and(|c| c.1.elapsed().as_secs() >= 4) {
                                    view.confirm = None;
                                    cx.notify();
                                }
                            });
                            if alive.is_err() {
                                break;
                            }
                        }
                    })
                    .detach();
                    Leakwatch::new(load_actions())
                })
            },
        )
        .unwrap();
        cx.activate(true);
    });
}

fn load_actions() -> Vec<Action> {
    let path = model::data_dir().join("actions.txt");
    if !path.exists() {
        let _ = std::fs::create_dir_all(model::data_dir());
        let _ = std::fs::write(
            &path,
            "# One button per line:  label | admin or user | PowerShell command\n\
             # admin opens an elevated window (UAC prompt), user opens a normal one. Examples:\n\
             # Restart Explorer | user | Stop-Process -Name explorer -Force\n\
             # Kernel trace | admin | & 'C:\\path\\to\\kernel-trace.ps1'\n",
        );
    }
    std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let mut parts = l.splitn(3, '|').map(str::trim);
            let label = parts.next()?.to_string();
            let admin = parts.next()? == "admin";
            let command = parts.next()?.to_string();
            Some(Action { label, admin, command })
        })
        .collect()
}

// ---------------------------------------------------------------- analysis

struct ProcTrend {
    handles_ph: f64,
    private_ph: f64,
    covered: f64,
}

impl Leakwatch {
    fn ingest(&mut self, mut s: Snapshot) {
        if self.demo.is_some() && self.history.persist {
            // First demo sample: stop saving history and draw a week-long climb, the way the leak grew.
            self.history.persist = false;
            let z = self.history.system.entry(Metric::Zombies).or_default();
            z.seed_ramp(s.t, 7.0 * 86400.0, 400.0, s.zombies as f64 + 32_700.0);
        }
        if self.demo == Some(false) {
            inject_demo(&mut s);
        }
        self.history.record(&s);
        self.latest = Some(s);
        self.scan_wanted_tags();
        self.check_alerts();
    }

    fn scan_wanted_tags(&self) {
        for tag in self.wanted_tags() {
            let mut map = self.tag_drivers.lock().unwrap();
            if map.contains_key(&tag) {
                continue;
            }
            map.insert(tag.clone(), None);
            let shared = self.tag_drivers.clone();
            std::thread::spawn(move || {
                let hits = sys::drivers_with_tag(&tag);
                shared.lock().unwrap().insert(tag, Some(hits));
            });
        }
    }

    fn run_act(&mut self, key: &str, watch: Metric, act: &findings::Act) {
        let destructive = !matches!(act.run, findings::Run::Open(_));
        if self.demo.is_some() {
            if destructive {
                self.demo = Some(true);
                self.record_act(key, watch, &act.label);
            }
            return;
        }
        let ok = match &act.run {
            findings::Run::Kill(pids) => pids.iter().filter(|&&p| sys::kill(p)).count() > 0,
            findings::Run::Elevated(cmd) => sys::run_elevated(cmd),
            findings::Run::Open(target) => {
                sys::open(target);
                true
            }
        };
        if !ok {
            self.flash(format!("{}: cancelled or not allowed", act.label));
            return;
        }
        if destructive {
            self.record_act(key, watch, &act.label);
        }
    }

    fn record_act(&mut self, key: &str, watch: Metric, label: &str) {
        let Some(s) = &self.latest else { return };
        let before = watch.value(s).unwrap_or(0.0);
        self.acted.insert(key.to_string(), Acted { at: s.t, label: label.to_string(), metric: watch, before });
        if self.demo.is_some() {
            return;
        }
        let lines: Vec<String> = self
            .acted
            .iter()
            .map(|(k, a)| format!("{k}\t{:.0}\t{}\t{:.0}\t{}", a.at, a.metric.csv(), a.before, a.label))
            .collect();
        let _ = std::fs::write(model::data_dir().join("acted.txt"), lines.join("\n"));
    }

    fn ignore(&mut self, key: &str, on: bool) {
        if on {
            self.ignored.insert(key.to_string());
        } else {
            self.ignored.remove(key);
        }
        let lines: Vec<&str> = self.ignored.iter().map(String::as_str).collect();
        let _ = std::fs::write(model::data_dir().join("ignored.txt"), lines.join("\n"));
    }

    fn metric_points(&self, m: Metric) -> Vec<(f64, f64)> {
        self.history.system.get(&m).map(|s| s.window(self.span.secs())).unwrap_or_default()
    }

    fn metric_level(&self, m: Metric, s: &Snapshot) -> (Level, f64, f64) {
        let pts = self.metric_points(m);
        let (slope, covered) = slope_per_hour(&pts);
        let v = m.value(s).unwrap_or(0.0);
        if m.limit(s).is_some_and(|l| v > l) {
            return (Level::Over, slope, covered);
        }
        let sustained = covered >= (self.span.secs() * 0.5).min(1800.0);
        if sustained && m.growth_alarm().is_some_and(|a| slope > a) {
            return (Level::Growing, slope, covered);
        }
        (Level::Quiet, slope, covered)
    }

    fn proc_trend(&self, p: &ProcRow) -> ProcTrend {
        let Some(h) = self.history.procs.get(&p.key) else {
            return ProcTrend { handles_ph: 0.0, private_ph: 0.0, covered: 0.0 };
        };
        let secs = self.span.secs().min(86400.0);
        let (handles_ph, covered) = slope_per_hour(&h.handles.window(secs));
        let (private_ph, _) = slope_per_hour(&h.private.window(secs));
        ProcTrend { handles_ph, private_ph, covered }
    }

    fn proc_level(&self, p: &ProcRow, t: &ProcTrend, live: u32) -> Level {
        if p.pid > 4 && p.process_handles > live + 200 {
            return Level::Over;
        }
        if t.covered >= 1200.0 && (t.handles_ph > 2000.0 || t.private_ph > 512.0 * 1048576.0) {
            return Level::Growing;
        }
        Level::Quiet
    }

    fn check_alerts(&mut self) {
        let Some(s) = self.latest.clone() else { return };
        for f in self.findings(&s) {
            let last = self.alerted.get(&f.key).copied().unwrap_or(0.0);
            if s.t - last > 1800.0 {
                self.alerted.insert(f.key.clone(), s.t);
                if self.demo.is_none() {
                    sys::toast(&f.title, &f.detail);
                }
            }
        }
    }

    fn flash(&mut self, msg: impl Into<String>) {
        self.status = Some((msg.into(), Instant::now()));
    }

    /// First click arms, second click within 4 s runs.
    fn confirmed(&mut self, key: &str) -> bool {
        if self.confirm.as_ref().is_some_and(|(k, t)| k == key && t.elapsed().as_secs() < 4) {
            self.confirm = None;
            true
        } else {
            self.confirm = Some((key.to_string(), Instant::now()));
            false
        }
    }

    fn armed(&self, key: &str) -> bool {
        self.confirm.as_ref().is_some_and(|(k, t)| k == key && t.elapsed().as_secs() < 4)
    }

    /// Every process of the given projects, their children, and the npm/cmd wrappers that launched them.
    fn dev_tree(&self, s: &Snapshot, projects: &HashSet<String>) -> Vec<u32> {
        let by_pid: HashMap<u32, &ProcRow> = s.procs.iter().map(|p| (p.pid, p)).collect();
        let mut kids: HashMap<u32, Vec<u32>> = HashMap::new();
        for p in &s.procs {
            kids.entry(p.ppid).or_default().push(p.pid);
        }
        let mut set: HashSet<u32> = HashSet::new();
        fn add(pid: u32, kids: &HashMap<u32, Vec<u32>>, set: &mut HashSet<u32>) {
            if set.insert(pid) {
                for k in kids.get(&pid).into_iter().flatten() {
                    add(*k, kids, set);
                }
            }
        }
        for p in s.procs.iter().filter(|p| p.project.as_ref().is_some_and(|x| projects.contains(x))) {
            add(p.pid, &kids, &mut set);
            let mut cur = by_pid.get(&p.ppid).copied();
            while let Some(c) = cur {
                let n = c.name.to_ascii_lowercase();
                let wrapper = c.cmdline.as_deref().is_some_and(|l| {
                    let l = l.to_ascii_lowercase();
                    l.contains("npm-cli") || l.contains("npx-cli") || l.contains("npm run") || l.contains("concurrently")
                });
                if (n == "node.exe" || n == "cmd.exe") && (wrapper || c.project.is_some()) && !set.contains(&c.pid) {
                    add(c.pid, &kids, &mut set);
                    cur = by_pid.get(&c.ppid).copied();
                } else {
                    break;
                }
            }
        }
        set.into_iter().collect()
    }

    fn report(&self) -> String {
        let Some(s) = &self.latest else { return String::new() };
        let mut out = format!(
            "leakwatch report, uptime {}, window {}\n\n",
            fmt_age(s.uptime as f64),
            self.span.label()
        );
        for m in Metric::ALL {
            let Some(v) = m.value(s) else { continue };
            let (lvl, slope, _) = self.metric_level(m, s);
            let flag = match lvl {
                Level::Over => "  << over limit",
                Level::Growing => "  << growing",
                Level::Quiet => "",
            };
            out += &format!("{:<22} {:>12}  {:>14}/h{}\n", m.label(), fmt_metric(m, v), fmt_rate(m, slope), flag);
        }
        out += "\nProcess handles held (zombie holders):\n";
        let mut holders: Vec<&ProcRow> = s.procs.iter().filter(|p| p.pid > 4).collect();
        holders.sort_by_key(|p| std::cmp::Reverse(p.process_handles));
        for p in holders.iter().take(5) {
            out += &format!("  {:<28} pid {:>6}  {:>6} process / {:>6} thread handles  {}\n", p.name, p.pid, p.process_handles, p.thread_handles, p.services.join(", "));
        }
        out += "\nFastest growing (handles/h, private/h):\n";
        let mut grow: Vec<(&ProcRow, ProcTrend)> = s.procs.iter().map(|p| (p, self.proc_trend(p))).collect();
        grow.retain(|(_, t)| growth_score(t) > 0.0);
        grow.sort_by(|a, b| growth_score(&b.1).total_cmp(&growth_score(&a.1)));
        if grow.is_empty() {
            out += "  nothing yet (needs a few minutes of samples)
";
        }
        for (p, t) in grow.iter().take(8) {
            out += &format!("  {:<28} pid {:>6}  handles {:>7} ({:+.0}/h)  private {} ({}/h)\n", p.name, p.pid, p.handles, t.handles_ph, fmt_bytes(p.private as f64), fmt_bytes(t.private_ph));
        }
        out += "\nLargest kernel pool tags:\n";
        let mut pool = s.pool.clone();
        pool.sort_by_key(|t| std::cmp::Reverse(t.nonpaged + t.paged));
        for t in pool.iter().take(8) {
            out += &format!("  {}  nonpaged {}  paged {}  allocations {}\n", t.tag, fmt_bytes(t.nonpaged as f64), fmt_bytes(t.paged as f64), fmt_count(t.allocs as f64));
        }
        let devs = dev_groups(s);
        if !devs.is_empty() {
            out += "\nDev servers:\n";
            for g in devs {
                out += &format!("  {:<24} {} processes  {}  {}\n", g.project, g.count, fmt_bytes(g.private as f64), g.copies.join("; "));
            }
        }
        out
    }
}

/// Demo data: the case from "Restarting fixes Windows": a mouse-software service holding 32,700 exited processes.
fn inject_demo(s: &mut Snapshot) {
    s.zombies += 32_700;
    s.process_objects += 32_700;
    s.system_cpu = 112.0;
    s.procs.push(ProcRow {
        key: (999_999, 1),
        pid: 999_999,
        ppid: 0,
        name: "GameManagerService.exe".into(),
        handles: 64_210,
        private: 96 * 1048576,
        threads: 41,
        cpu_pct: 0.4,
        age_secs: 20.0 * 86400.0,
        session: 0,
        process_handles: s.live_processes + 32_700,
        thread_handles: 29_400,
        services: vec!["Razer Game Manager Service".into()],
        service_names: vec!["Razer Game Manager Service".into()],
        stoppable: true,
        project: None,
        cmdline: None,
    });
}

fn growth_score(t: &ProcTrend) -> f64 {
    if t.covered < 300.0 {
        return 0.0;
    }
    (t.handles_ph / 1000.0).max(t.private_ph / (100.0 * 1048576.0))
}

struct DevGroup {
    project: String,
    count: usize,
    private: u64,
    oldest: f64,
    copies: Vec<String>,
    duplicated: bool,
}

/// `"node" "C:\...\node_modules\.bin\..\vite\bin\vite.js" --port 5173` -> `vite --port 5173`
fn short_command(cmd: &str) -> String {
    let lower = cmd.to_ascii_lowercase();
    if let Some(i) = lower.rfind("node_modules") {
        let rest = &cmd[i + "node_modules".len()..];
        let rest = rest.trim_start_matches(['\\', '/']);
        let rest = rest.strip_prefix(".bin\\..\\").or_else(|| rest.strip_prefix(".bin/../")).unwrap_or(rest);
        let pkg: String = rest.chars().take_while(|c| *c != '\\' && *c != '/').collect();
        let args = rest.find(char::is_whitespace).map(|j| rest[j..].trim()).unwrap_or("");
        let args = args.trim_start_matches('"').trim();
        return format!("{pkg} {args}").trim().chars().take(60).collect();
    }
    let tail: String = cmd.chars().rev().take(60).collect::<Vec<_>>().into_iter().rev().collect();
    tail
}

fn dev_groups(s: &Snapshot) -> Vec<DevGroup> {
    let mut groups: HashMap<String, Vec<&ProcRow>> = HashMap::new();
    for p in &s.procs {
        if let Some(proj) = &p.project {
            if p.name.eq_ignore_ascii_case("node.exe") || p.name.eq_ignore_ascii_case("bun.exe") || p.name.eq_ignore_ascii_case("deno.exe") || p.name.eq_ignore_ascii_case("python.exe") {
                groups.entry(proj.clone()).or_default().push(p);
            }
        }
    }
    let mut out: Vec<DevGroup> = groups
        .into_iter()
        .map(|(project, ps)| {
            let mut cmds: HashMap<String, usize> = HashMap::new();
            for p in &ps {
                *cmds.entry(short_command(p.cmdline.as_deref().unwrap_or(""))).or_default() += 1;
            }
            let duplicated = cmds.values().any(|&n| n > 1);
            let mut copies: Vec<(String, usize)> = cmds.into_iter().collect();
            copies.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            DevGroup {
                project,
                count: ps.len(),
                private: ps.iter().map(|p| p.private).sum(),
                oldest: ps.iter().map(|p| p.age_secs).fold(0.0, f64::max),
                copies: copies.into_iter().map(|(c, n)| if n > 1 { format!("{n}× {c}") } else { c }).collect(),
                duplicated,
            }
        })
        .collect();
    out.sort_by(|a, b| b.private.cmp(&a.private));
    out
}

pub fn fmt_metric(m: Metric, v: f64) -> String {
    if m.is_bytes() {
        fmt_bytes(v)
    } else if m == Metric::SystemCpu {
        format!("{v:.0}%")
    } else {
        fmt_count(v)
    }
}

fn fmt_rate(m: Metric, slope: f64) -> String {
    let sign = if slope >= 0.0 { "+" } else { "-" };
    if m.is_bytes() {
        format!("{sign}{}", fmt_bytes(slope.abs()))
    } else if m == Metric::SystemCpu {
        format!("{sign}{:.1}%", slope.abs())
    } else {
        format!("{sign}{}", fmt_count(slope.abs()))
    }
}

// ---------------------------------------------------------------- drawing helpers

fn c(hex: u32) -> Rgba {
    gpui::rgba(hex)
}

pub fn sparkline(pts: Vec<(f64, f64)>, color: u32, w: f32, h: f32) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            if pts.len() < 2 {
                return;
            }
            let t0 = pts[0].0;
            let t1 = pts[pts.len() - 1].0.max(t0 + 1.0);
            let lo = pts.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
            let hi = pts.iter().map(|p| p.1).fold(f64::NEG_INFINITY, f64::max);
            let range = (hi - lo).max(((hi + lo) / 2.0).abs() * 0.05).max(1.0);
            let mid = (hi + lo) / 2.0;
            let bw = f32::from(bounds.size.width);
            let bh = f32::from(bounds.size.height) - 2.0;
            // Thin the points to roughly one per pixel.
            let step = (pts.len() / bw.max(1.0) as usize).max(1);
            let mut b = PathBuilder::stroke(px(1.25));
            let mut first = true;
            for (i, &(t, v)) in pts.iter().enumerate() {
                if i % step != 0 && i != pts.len() - 1 {
                    continue;
                }
                let x = ((t - t0) / (t1 - t0)) as f32 * bw;
                let y = (0.5 - (v - mid) / range) as f32 * bh + 1.0;
                let pt = point(bounds.origin.x + px(x), bounds.origin.y + px(y));
                if first {
                    b.move_to(pt);
                    first = false;
                } else {
                    b.line_to(pt);
                }
            }
            if let Ok(path) = b.build() {
                window.paint_path(path, c(color));
            }
        },
    )
    .w(px(w))
    .h(px(h))
}

fn panel(title: &str, note: Option<String>) -> Div {
    div()
        .flex()
        .flex_col()
        .bg(c(PANEL))
        .border_1()
        .border_color(c(LINE))
        .rounded_md()
        .child(
            div()
                .flex()
                .items_baseline()
                .justify_between()
                .px_4()
                .py_2()
                .border_b_1()
                .border_color(c(LINE))
                .child(div().text_sm().text_color(c(TEXT)).child(title.to_string()))
                .children(note.map(|n| div().text_xs().text_color(c(FAINT)).child(n))),
        )
}

fn num(s: impl Into<SharedString>) -> Div {
    div().font_family(MONO).text_sm().child(s.into())
}

fn cell(w: f32) -> Div {
    div().w(px(w)).flex_shrink_0()
}

impl Leakwatch {
    fn button(
        &self,
        id: impl Into<SharedString>,
        label: impl Into<SharedString>,
        tone: u32,
        cx: &mut Context<Self>,
        f: impl Fn(&mut Self, &mut Context<Self>) + 'static,
    ) -> Stateful<Div> {
        let id: SharedString = id.into();
        div()
            .id(id)
            .px_2()
            .py(px(3.))
            .rounded_sm()
            .border_1()
            .border_color(c(LINE))
            .text_xs()
            .text_color(c(tone))
            .cursor_pointer()
            .hover(|s| s.bg(c(LINE)))
            .child(label.into())
            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                f(this, cx);
                cx.notify();
            }))
    }

    fn system_panel(&self, s: &Snapshot) -> Div {
        let mut p = panel("System", Some(format!("change per hour over the last {}", self.span.label())));
        for m in Metric::ALL {
            let Some(v) = m.value(s) else { continue };
            let (lvl, slope, covered) = self.metric_level(m, s);
            let pts = self.metric_points(m);
            let extra = match m {
                Metric::Commit => format!(" / {}", fmt_bytes(s.mem.commit_limit as f64)),
                Metric::Available => format!(" / {}", fmt_bytes(s.mem.physical as f64)),
                Metric::GpuMem => s
                    .gpu
                    .map(|g| format!(" / {}  {:.0} °C {:.0} W", fmt_bytes(g.mem_total_mb * 1048576.0), g.temp_c, g.power_w))
                    .unwrap_or_default(),
                _ => String::new(),
            };
            let rate = if covered < 600.0 { "collecting".to_string() } else { format!("{}/h", fmt_rate(m, slope)) };
            p = p.child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_4()
                    .py_2()
                    .border_b_1()
                    .border_color(c(LINE))
                    .child(
                        cell(210.)
                            .flex()
                            .flex_col()
                            .child(div().text_sm().text_color(c(TEXT)).child(m.label()))
                            .child(div().text_xs().text_color(c(FAINT)).child(m.hint())),
                    )
                    .child(
                        cell(190.).flex().items_baseline().child(num(fmt_metric(m, v)).text_color(c(lvl.color()))).child(
                            div().font_family(MONO).text_xs().text_color(c(FAINT)).child(extra),
                        ),
                    )
                    .child(sparkline(pts, if lvl == Level::Quiet { MUTED } else { lvl.color() }, 220., 30.))
                    .child(cell(120.).flex().justify_end().child(num(rate).text_color(c(if lvl == Level::Quiet { MUTED } else { lvl.color() })))),
            );
        }
        p
    }

    /// Stop for processes hosting a few services, End for the user's own processes, nothing for
    /// shared service hosts and system processes, where either would take Windows down with them.
    fn kill_button(&self, p: &ProcRow, cx: &mut Context<Self>) -> Option<Stateful<Div>> {
        if p.pid <= 4 || (p.services.is_empty() && p.session == 0) || (!p.services.is_empty() && (!p.stoppable || p.services.len() > 3)) {
            return None;
        }
        Some(self.kill_button_inner(p, cx))
    }

    fn kill_button_inner(&self, p: &ProcRow, cx: &mut Context<Self>) -> Stateful<Div> {
        if !p.services.is_empty() {
            let names = p.services.clone();
            let key = format!("svc-{}", p.pid);
            let armed = self.armed(&key);
            let label = if armed { "Confirm (admin)".to_string() } else if names.len() == 1 { format!("Stop {}", names[0]) } else { format!("Stop {} services", names.len()) };
            return self.button(key.clone(), label, if armed { RED } else { MUTED }, cx, move |this, _| {
                if this.confirmed(&key) {
                    let list = names.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>().join(",");
                    let ok = sys::run_elevated(&format!("Stop-Service {list} -Force; Get-Service {list} | Format-Table Name,Status"));
                    this.flash(if ok { "Stopping services in an admin window" } else { "Cancelled" });
                }
            });
        }
        let pid = p.pid;
        let name = p.name.clone();
        let key = format!("kill-{pid}");
        let armed = self.armed(&key);
        self.button(key.clone(), if armed { "Confirm end" } else { "End" }, if armed { RED } else { MUTED }, cx, move |this, _| {
            if this.confirmed(&key) {
                let ok = sys::kill(pid);
                this.flash(if ok { format!("Ended {name} ({pid})") } else { format!("Could not end {name}: needs admin") });
            }
        })
    }

    fn process_panel(&self, s: &Snapshot, cx: &mut Context<Self>) -> Div {
        let mut tabs = div().flex().gap_1();
        for (t, label) in [
            (Tab::Growing, "Growing"),
            (Tab::Holders, "Zombie holders"),
            (Tab::Handles, "Most handles"),
            (Tab::Memory, "Most memory"),
        ] {
            let on = self.tab == t;
            tabs = tabs.child(
                div()
                    .id(SharedString::from(format!("tab-{label}")))
                    .px_2()
                    .py(px(3.))
                    .rounded_sm()
                    .text_xs()
                    .cursor_pointer()
                    .text_color(c(if on { TEXT } else { MUTED }))
                    .bg(c(if on { LINE } else { PANEL }))
                    .child(label)
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.tab = t;
                        cx.notify();
                    })),
            );
        }

        let mut rows: Vec<(&ProcRow, ProcTrend)> =
            s.procs.iter().filter(|p| p.pid != 0).map(|p| (p, self.proc_trend(p))).collect();
        match self.tab {
            Tab::Growing => {
                rows.retain(|(_, t)| growth_score(t) > 0.0);
                rows.sort_by(|a, b| growth_score(&b.1).total_cmp(&growth_score(&a.1)));
            }
            Tab::Holders => rows.sort_by_key(|(p, _)| std::cmp::Reverse(p.process_handles + p.thread_handles)),
            Tab::Handles => rows.sort_by_key(|(p, _)| std::cmp::Reverse(p.handles)),
            Tab::Memory => rows.sort_by_key(|(p, _)| std::cmp::Reverse(p.private)),
        }
        rows.truncate(16);

        let head = |t: &str, w: f32| cell(w).text_xs().text_color(c(FAINT)).child(t.to_string());
        let note = match self.tab {
            Tab::Growing => "sorted by handle or memory growth".to_string(),
            Tab::Holders => format!("{} processes alive; holding more process handles than that means holding zombies", s.live_processes),
            Tab::Handles => "sorted by open handles".to_string(),
            Tab::Memory => "sorted by private (committed) memory".to_string(),
        };
        let mut p = panel("Processes", None).child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .px_4()
                .py_2()
                .child(tabs)
                .child(div().text_xs().text_color(c(FAINT)).child(note)),
        );
        p = p.child(
            div()
                .flex()
                .gap_3()
                .px_4()
                .py_1()
                .border_b_1()
                .border_color(c(LINE))
                .child(div().flex_1().text_xs().text_color(c(FAINT)).child("Process"))
                .child(head("Handles", 70.))
                .child(head("per hour", 70.))
                .child(head("Private", 70.))
                .child(head("per hour", 74.))
                .child(head("Proc / thread handles", 120.))
                .child(head("CPU", 44.))
                .child(head("Running", 60.))
                .child(head("", 150.)),
        );
        if rows.is_empty() {
            p = p.child(div().px_4().py_3().text_sm().text_color(c(MUTED)).child(
                "Nothing is growing yet. Growth shows after a few minutes of samples.",
            ));
        }
        for (r, t) in rows {
            let lvl = self.proc_level(r, &t, s.live_processes);
            let h = self.history.procs.get(&r.key);
            let spark = h
                .map(|h| match self.tab {
                    Tab::Memory => h.private.window(self.span.secs().min(86400.0)),
                    _ => h.handles.window(self.span.secs().min(86400.0)),
                })
                .unwrap_or_default();
            let sub = if !r.services.is_empty() {
                r.services.join(", ")
            } else if let Some(pr) = &r.project {
                format!("{pr}: {}", short_command(r.cmdline.as_deref().unwrap_or("")))
            } else {
                format!("pid {}", r.pid)
            };
            let tone = |v: f64, a: f64| c(if t.covered >= 1200.0 && v > a { AMBER } else if v.abs() < 1e-9 || t.covered < 600.0 { FAINT } else { MUTED });
            let early = t.covered < 600.0;
            let holder_color = if lvl == Level::Over { RED } else if r.process_handles > 1000 { AMBER } else { MUTED };
            p = p.child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_4()
                    .py(px(5.))
                    .border_b_1()
                    .border_color(c(LINE))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .min_w_0()
                                    .flex_1()
                                    .child(div().text_sm().text_color(c(lvl.color())).truncate().child(r.name.clone()))
                                    .child(div().text_xs().text_color(c(FAINT)).truncate().child(sub)),
                            )
                            .child(sparkline(spark, if lvl == Level::Quiet { FAINT } else { lvl.color() }, 90., 22.)),
                    )
                    .child(cell(70.).child(num(fmt_count(r.handles as f64)).text_color(c(TEXT))))
                    .child(cell(70.).child(num(if early { "…".to_string() } else { format!("{:+.0}", t.handles_ph) }).text_xs().text_color(tone(t.handles_ph, 2000.0))))
                    .child(cell(70.).child(num(fmt_bytes(r.private as f64)).text_color(c(TEXT))))
                    .child(cell(74.).child(
                        num(if early { "…".to_string() } else { format!("{}{}", if t.private_ph >= 0.0 { "+" } else { "-" }, fmt_bytes(t.private_ph.abs())) })
                            .text_xs()
                            .text_color(tone(t.private_ph, 512.0 * 1048576.0)),
                    ))
                    .child(cell(120.).child(
                        num(format!("{} / {}", fmt_count(r.process_handles as f64), fmt_count(r.thread_handles as f64)))
                            .text_color(c(holder_color)),
                    ))
                    .child(cell(44.).child(num(format!("{:.0}%", r.cpu_pct)).text_xs().text_color(c(MUTED))))
                    .child(cell(60.).child(num(fmt_age(r.age_secs)).text_xs().text_color(c(MUTED))))
                    .child(cell(150.).flex().justify_end().children(self.kill_button(r, cx))),
            );
        }
        p
    }

    fn dev_panel(&self, s: &Snapshot, cx: &mut Context<Self>) -> Div {
        let groups = dev_groups(s);
        let total: u64 = groups.iter().map(|g| g.private).sum();
        let mut p = panel(
            "Dev servers",
            Some(if groups.is_empty() { "none running".into() } else { format!("{} in {} projects", fmt_bytes(total as f64), groups.len()) }),
        );
        for g in &groups {
            let key = format!("dev-{}", g.project);
            let armed = self.armed(&key);
            let project = g.project.clone();
            let k2 = key.clone();
            p = p.child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_4()
                    .py(px(6.))
                    .border_b_1()
                    .border_color(c(LINE))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .items_baseline()
                                    .child(div().text_sm().text_color(c(if g.duplicated { AMBER } else { TEXT })).child(g.project.clone()))
                                    .child(div().text_xs().text_color(c(FAINT)).child(format!(
                                        "{} processes, {}, oldest {}",
                                        g.count,
                                        fmt_bytes(g.private as f64),
                                        fmt_age(g.oldest)
                                    ))),
                            )
                            .children(g.copies.iter().take(4).map(|cmd| {
                                div()
                                    .font_family(MONO)
                                    .text_xs()
                                    .truncate()
                                    .text_color(c(if cmd.contains('×') { AMBER } else { FAINT }))
                                    .child(cmd.clone())
                            })),
                    )
                    .child(self.button(k2, if armed { "Confirm stop" } else { "Stop" }, if armed { RED } else { MUTED }, cx, move |this, _| {
                        if this.confirmed(&key) {
                            this.stop_projects(&[project.clone()].into_iter().collect());
                        }
                    })),
            );
        }
        if groups.len() > 1 {
            let all: HashSet<String> = groups.iter().map(|g| g.project.clone()).collect();
            let armed = self.armed("dev-all");
            p = p.child(div().flex().justify_end().px_4().py_2().child(self.button(
                "dev-all",
                if armed { "Confirm stop all" } else { "Stop all dev servers" },
                if armed { RED } else { MUTED },
                cx,
                move |this, _| {
                    if this.confirmed("dev-all") {
                        this.stop_projects(&all);
                    }
                },
            )));
        }
        p
    }

    fn stop_projects(&mut self, projects: &HashSet<String>) {
        let Some(s) = self.latest.clone() else { return };
        let pids = self.dev_tree(&s, projects);
        let freed: u64 = s.procs.iter().filter(|p| pids.contains(&p.pid)).map(|p| p.private).sum();
        let killed = pids.iter().filter(|&&pid| sys::kill(pid)).count();
        self.flash(format!("Stopped {killed} processes, about {} freed", fmt_bytes(freed as f64)));
    }

    fn pool_panel(&self, s: &Snapshot) -> Div {
        let mut tags = s.pool.clone();
        tags.sort_by_key(|t| std::cmp::Reverse(t.nonpaged + t.paged));
        tags.truncate(8);
        let mut p = panel("Kernel pool by tag", Some("drivers tag their allocations".into()));
        for t in tags {
            let pts = self.history.pool.get(&t.tag).map(|x| x.window(self.span.secs())).unwrap_or_default();
            let (slope, covered) = slope_per_hour(&pts);
            let growing = covered >= 1200.0 && slope > 20.0 * 1048576.0;
            let col = if growing { AMBER } else { MUTED };
            p = p.child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_4()
                    .py(px(4.))
                    .border_b_1()
                    .border_color(c(LINE))
                    .child(cell(48.).child(num(t.tag.clone()).text_color(c(if growing { AMBER } else { TEXT }))))
                    .child(div().flex_1().child(num(format!(
                        "{} np · {} p",
                        fmt_bytes(t.nonpaged as f64),
                        fmt_bytes(t.paged as f64)
                    )).text_xs().text_color(c(MUTED))))
                    .child(sparkline(pts, col, 80., 18.))
                    .child(cell(80.).flex().justify_end().child(num(if covered < 600.0 { "…".to_string() } else { format!("{}/h", fmt_rate(Metric::Paged, slope)) }).text_xs().text_color(c(col)))),
            );
        }
        p
    }

    fn types_panel(&self, s: &Snapshot) -> Div {
        let mut types = s.types.clone();
        types.sort_by_key(|t| std::cmp::Reverse(t.objects));
        types.truncate(8);
        let mut p = panel("Kernel objects by type", Some("what the handles point at".into()));
        for t in types {
            let pts = self.history.types.get(&t.name).map(|x| x.window(self.span.secs())).unwrap_or_default();
            let (slope, covered) = slope_per_hour(&pts);
            let growing = covered >= 1200.0 && slope > 2000.0;
            let col = if growing { AMBER } else { MUTED };
            p = p.child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_4()
                    .py(px(4.))
                    .border_b_1()
                    .border_color(c(LINE))
                    .child(div().flex_1().text_sm().text_color(c(if growing { AMBER } else { TEXT })).child(t.name.clone()))
                    .child(cell(70.).flex().justify_end().child(num(fmt_count(t.objects as f64)).text_xs().text_color(c(MUTED))))
                    .child(sparkline(pts, col, 80., 18.))
                    .child(cell(70.).flex().justify_end().child(num(if covered < 600.0 { "…".to_string() } else { format!("{}/h", fmt_rate(Metric::Handles, slope)) }).text_xs().text_color(c(col)))),
            );
        }
        p
    }

    fn details(&mut self, s: &Snapshot, window: &mut Window, cx: &mut Context<Self>) -> Div {
        self.fit_window(window, 1240., 900.);
        let back = self.text_button("back", "‹ Status", cx, |this, _| this.page = Page::Status);
        let mut d = div().flex().flex_col().gap_4().px_8().py_6().child(back);
        let mut spans = div().flex().gap_1().items_center().child(div().text_xs().text_color(c(FAINT)).mr_2().child("Trends over"));
        for sp in [Span::H1, Span::H6, Span::D1, Span::D7] {
            let on = self.span == sp;
            spans = spans.child(
                div()
                    .id(SharedString::from(format!("span-{}", sp.label())))
                    .px_2()
                    .py(px(3.))
                    .rounded_sm()
                    .text_xs()
                    .cursor_pointer()
                    .text_color(c(if on { TEXT } else { MUTED }))
                    .bg(c(if on { LINE } else { BG }))
                    .child(sp.label())
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.span = sp;
                        cx.notify();
                    })),
            );
        }
        let folder = self.button("folder", "Data folder", FAINT, cx, |_, _| {
            let _ = std::process::Command::new("explorer.exe").arg(model::data_dir()).spawn();
        });
        d = d.child(div().flex().justify_between().items_center().child(spans).child(folder));
        if !self.ignored.is_empty() {
            let mut row = div().flex().flex_wrap().gap_2().items_center().child(div().text_xs().text_color(c(FAINT)).child("Ignored:"));
            for k in self.ignored.iter() {
                let k2 = k.clone();
                row = row.child(self.button(format!("unignore-{k}"), format!("{k} ✕"), FAINT, cx, move |this, _| this.ignore(&k2, false)));
            }
            d = d.child(row);
        }
        d.child(
            div()
                .flex()
                .gap_4()
                .items_start()
                .child(div().flex_1().min_w_0().child(self.system_panel(s)))
                .child(
                    div()
                        .w(px(420.))
                        .flex_shrink_0()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .child(self.dev_panel(s, cx))
                        .child(self.pool_panel(s))
                        .child(self.types_panel(s)),
                ),
        )
        .child(self.process_panel(s, cx))
    }
}

impl Render for Leakwatch {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let root = div()
            .id("root")
            .size_full()
            .overflow_y_scroll()
            .bg(gpui::rgba(0x1c1c1ee0))
            .text_color(c(TEXT))
            .font_family(status::BODY);
        let Some(s) = self.latest.clone() else {
            return root.child(div().p_8().text_color(c(MUTED)).child("Taking the first sample…"));
        };
        match self.page {
            Page::Status => root.child(self.render_status(&s, window, cx)),
            Page::Details => root.child(self.details(&s, window, cx)),
        }
    }
}
