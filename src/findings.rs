//! Turns samples into findings: a named culprit, what it costs, and what to do about it now and for good.

use std::collections::{HashMap, HashSet};

use crate::model::{Metric, ProcRow, Snapshot, fmt_age, fmt_bytes, fmt_count, slope_per_hour};
use crate::{Leakwatch, Level};

/// Growth checks need this much history before they can say "keeps growing".
pub const MIN_WATCH_SECS: f64 = 1800.0;

#[derive(Clone)]
pub enum Run {
    Kill(Vec<u32>),
    Elevated(String),
    Open(String),
}

#[derive(Clone)]
pub struct Act {
    pub label: String,
    /// What pressing it does, in a few words: "frees them now", "fixes it for good".
    pub hint: String,
    pub run: Run,
}

pub struct Finding {
    pub key: String,
    pub level: Level,
    /// One sentence for notifications and the report.
    pub title: String,
    /// The number that is wrong, shown large: "32,700".
    pub figure: String,
    /// What the figure counts, naming the culprit: "closed programs held by Razer Game Manager Service".
    pub subject: String,
    pub detail: String,
    pub now: Option<Act>,
    pub fix: Option<Act>,
    pub note: Option<String>,
    /// What the problem costs, drawn as a gauge: label, value, fill from 0 to 1.
    pub impact: Option<(String, String, f32)>,
    /// The number that should drop once the problem is handled.
    pub watch: Metric,
}

/// "GameManagerService.exe" hosting "Razer Game Manager Service" -> "Razer Game Manager Service".
pub fn display_name(p: &ProcRow) -> String {
    match p.service_names.first() {
        Some(d) if !d.is_empty() && p.services.len() == 1 => d.clone(),
        _ => p.name.trim_end_matches(".exe").trim_end_matches(".EXE").to_string(),
    }
}

fn quote_list(names: &[String]) -> String {
    names.iter().map(|n| format!("'{}'", n.replace('\'', "''"))).collect::<Vec<_>>().join(",")
}

/// The "now" and "for good" actions for a process that is causing trouble.
fn process_actions(p: &ProcRow, now_hint: &str) -> (Option<Act>, Option<Act>, Option<String>) {
    if !p.services.is_empty() {
        if !p.stoppable || p.services.len() > 3 {
            return (
                None,
                None,
                Some(format!(
                    "{} hosts Windows services that cannot be stopped safely. Restarting Windows clears it.",
                    p.name
                )),
            );
        }
        let list = quote_list(&p.services);
        let undo = p.services.iter().map(|n| format!("Set-Service '{n}' -StartupType Automatic")).collect::<Vec<_>>().join("; ");
        return (
            Some(Act {
                label: "Restart service".into(),
                hint: format!("{now_hint}. The leak builds up again from zero."),
                run: Run::Elevated(format!("Restart-Service {list} -Force; Get-Service {list} | Format-Table Name,Status")),
            }),
            Some(Act {
                label: "Turn off".into(),
                hint: "Stops the service and keeps the service from starting with Windows.".into(),
                run: Run::Elevated(format!(
                    "Set-Service {list} -StartupType Disabled; Stop-Service {list} -Force; Get-Service {list} | Format-Table Name,Status,StartType; Write-Host \"Undo: {undo}\""
                )),
            }),
            None,
        );
    }
    if p.session == 0 {
        return (None, None, Some(format!("{} runs as a system process; restarting Windows clears it.", p.name)));
    }
    (
        Some(Act { label: format!("End {}", p.name), hint: format!("{now_hint}. Reopen the app when you need the app again."), run: Run::Kill(vec![p.pid]) }),
        Some(Act {
            label: "Remove from startup".into(),
            hint: "Opens Startup apps, where the app can be switched off.".into(),
            run: Run::Open("ms-settings:startupapps".into()),
        }),
        None,
    )
}

fn per_day(per_hour: f64) -> f64 {
    per_hour * 24.0
}

impl Leakwatch {
    pub fn findings(&self, s: &Snapshot) -> Vec<Finding> {
        let mut out = vec![];
        let live = s.live_processes;

        // 1. A process holding exited processes open.
        let zombie_pts = self.history.system.get(&Metric::Zombies).map(|x| x.window(86400.0)).unwrap_or_default();
        let (zombie_ph, zombie_cov) = slope_per_hour(&zombie_pts);
        let mut holders: Vec<&ProcRow> =
            s.procs.iter().filter(|p| p.pid > 4 && p.process_handles > live + 200).collect();
        holders.sort_by_key(|p| std::cmp::Reverse(p.process_handles));
        for p in holders.iter().take(2) {
            let held = (p.process_handles - live).min(s.zombies.max(0) as u32);
            let cost = if s.system_cpu >= 30.0 {
                format!("Windows is spending {:.1} CPU cores managing them, which shows up as stutter everywhere.", s.system_cpu / 100.0)
            } else {
                "Each one keeps kernel memory. Past a few thousand, games and the desktop start to stutter.".into()
            };
            let growth = if zombie_cov >= 7200.0 && zombie_ph > 10.0 {
                format!(" About {} more a day.", fmt_count(per_day(zombie_ph)))
            } else {
                String::new()
            };
            let (now, fix, note) = process_actions(p, "Frees them within a minute");
            out.push(Finding {
                key: format!("holder:{}", p.name),
                level: Level::Over,
                title: format!("{} is keeping {} closed programs in memory", display_name(p), fmt_count(held as f64)),
                figure: fmt_count(held as f64),
                subject: format!("closed programs held by {}", display_name(p)),
                detail: format!("{cost}{growth}"),
                now,
                fix,
                note,
                impact: Some(("Windows CPU".into(), format!("{:.1} cores", s.system_cpu / 100.0), (s.system_cpu / 200.0).clamp(0.0, 1.0) as f32)),
                watch: Metric::Zombies,
            });
        }

        // 2. Lots of zombies but nobody obviously holding them.
        if holders.is_empty() && s.zombies > 2000 {
            out.push(Finding {
                key: "zombies".into(),
                level: Level::Over,
                title: format!("{} closed programs are still held in memory", fmt_count(s.zombies as f64)),
                figure: fmt_count(s.zombies as f64),
                subject: "closed programs still held in memory".into(),
                detail: "No single program holds most of them. Open Details, Zombie holders, to see who holds the most.".into(),
                now: None,
                fix: None,
                note: Some("Restarting Windows clears them.".into()),
                impact: Some(("Windows CPU".into(), format!("{:.1} cores", s.system_cpu / 100.0), (s.system_cpu / 200.0).clamp(0.0, 1.0) as f32)),
                watch: Metric::Zombies,
            });
        }

        // 3 and 4. Processes whose handles or memory keep growing.
        for p in &s.procs {
            if p.pid <= 4 || holders.iter().any(|h| h.pid == p.pid) {
                continue;
            }
            let Some(h) = self.history.procs.get(&p.key) else { continue };
            let (hph, hcov) = slope_per_hour(&h.handles.window(86400.0));
            if hcov >= MIN_WATCH_SECS && hph > 1000.0 && p.handles > 10_000 {
                let (now, fix, note) = process_actions(p, "Frees the handles");
                out.push(Finding {
                    key: format!("handles:{}", p.name),
                    level: if p.handles > 50_000 { Level::Over } else { Level::Growing },
                    title: format!("{} keeps opening handles and never closes them", display_name(p)),
                    figure: fmt_count(p.handles as f64),
                    subject: format!("handles open in {}, {} more every hour", display_name(p), fmt_count(hph)),
                    detail: format!(
                        "{} open now, {} more every hour for the last {}. Leaked handles pin kernel memory until the program exits.",
                        fmt_count(p.handles as f64),
                        fmt_count(hph),
                        fmt_age(hcov)
                    ),
                    now,
                    fix,
                    note,
                    impact: None,
                    watch: Metric::Handles,
                });
                continue;
            }
            let (mph, mcov) = slope_per_hour(&h.private.window(86400.0));
            if mcov >= MIN_WATCH_SECS && mph > 200.0 * 1048576.0 && p.private > 1024 * 1048576 {
                let (now, fix, note) = process_actions(p, "Gives the memory back");
                out.push(Finding {
                    key: format!("memory:{}", p.name),
                    level: if p.private as f64 > s.mem.physical as f64 * 0.25 { Level::Over } else { Level::Growing },
                    title: format!("{} keeps using more memory", display_name(p)),
                    figure: fmt_bytes(p.private as f64),
                    subject: format!("used by {}, {} more every hour", display_name(p), fmt_bytes(mph)),
                    detail: format!(
                        "{} now, {} more every hour for the last {}. At this rate that is {} more by this time tomorrow.",
                        fmt_bytes(p.private as f64),
                        fmt_bytes(mph),
                        fmt_age(mcov),
                        fmt_bytes(per_day(mph))
                    ),
                    now,
                    fix,
                    note,
                    impact: Some(("Share of RAM".into(), format!("{:.0}%", p.private as f64 / s.mem.physical.max(1) as f64 * 100.0), (p.private as f64 / s.mem.physical.max(1) as f64).clamp(0.0, 1.0) as f32)),
                    watch: Metric::Commit,
                });
            }
        }

        // 5. A driver leaking kernel memory.
        for m in [Metric::Nonpaged, Metric::Paged] {
            let (lvl, slope, _) = self.metric_level(m, s);
            if lvl == Level::Quiet {
                continue;
            }
            let tag = self.fastest_pool_tag();
            let drivers = tag.as_ref().and_then(|t| self.tag_drivers.lock().unwrap().get(t).cloned()).flatten();
            let who = match (&tag, &drivers) {
                (_, Some(d)) if !d.is_empty() => d.iter().take(2).cloned().collect::<Vec<_>>().join(" or "),
                (Some(t), _) => format!("A driver (pool tag {t})"),
                _ => "A driver".into(),
            };
            let value = m.value(s).unwrap_or(0.0);
            out.push(Finding {
                key: format!("driver:{}", tag.clone().unwrap_or_else(|| m.csv().into())),
                level: lvl,
                title: format!("{who} is leaking kernel memory"),
                figure: fmt_bytes(value),
                subject: format!("kernel memory, {} more every hour, most likely {}", fmt_bytes(slope.max(0.0)), who.replacen("A driver", "a driver", 1)),
                detail: format!(
                    "{} is at {} and grows {} an hour. Kernel memory only comes back when Windows restarts.",
                    m.label(),
                    fmt_bytes(value),
                    fmt_bytes(slope.max(0.0))
                ),
                now: None,
                fix: Some(Act {
                    label: "Device Manager".into(),
                    hint: "Update or roll back that driver.".into(),
                    run: Run::Open("devmgmt.msc".into()),
                }),
                note: Some("Restarting Windows frees it for now.".into()),
                impact: None,
                watch: m,
            });
            break;
        }

        // 6. Committed memory running out.
        let limit = s.mem.commit_limit as f64;
        if limit > 0.0 && s.mem.commit as f64 > limit * 0.85 {
            let (slope, cov) = slope_per_hour(&self.history.system.get(&Metric::Commit).map(|x| x.window(3600.0)).unwrap_or_default());
            let left = limit - s.mem.commit as f64;
            let eta = if cov >= 900.0 && slope > 0.0 { format!(" At the current rate it runs out in {}.", fmt_age(left / slope * 3600.0)) } else { String::new() };
            let mut big: Vec<&ProcRow> = s.procs.iter().filter(|p| p.pid > 4).collect();
            big.sort_by_key(|p| std::cmp::Reverse(p.private));
            let names = big.iter().take(3).map(|p| format!("{} ({})", display_name(p), fmt_bytes(p.private as f64))).collect::<Vec<_>>().join(", ");
            out.push(Finding {
                key: "commit".into(),
                level: Level::Over,
                title: "Memory is about to run out".into(),
                figure: format!("{} of {}", fmt_bytes(s.mem.commit as f64), fmt_bytes(limit)),
                subject: "memory in use".into(),
                detail: format!("{} of {} is in use.{eta} Biggest: {names}.", fmt_bytes(s.mem.commit as f64), fmt_bytes(limit)),
                now: None,
                fix: None,
                note: Some("Programs start failing or freezing when it is full.".into()),
                impact: Some(("Memory".into(), format!("{:.0}%", s.mem.commit as f64 / limit * 100.0), (s.mem.commit as f64 / limit).clamp(0.0, 1.0) as f32)),
                watch: Metric::Commit,
            });
        }

        // 7. Windows itself busy with no zombie cause.
        if holders.is_empty() && self.metric_level(Metric::SystemCpu, s).0 == Level::Over {
            out.push(Finding {
                key: "kernel-cpu".into(),
                level: Level::Over,
                title: format!("Windows itself is using {:.1} CPU cores", s.system_cpu / 100.0),
                figure: format!("{:.1} cores", s.system_cpu / 100.0),
                subject: "used by Windows itself, not by any program".into(),
                detail: "This is time spent in drivers and the kernel, not in any program. It is usually a driver.".into(),
                now: None,
                fix: None,
                note: Some("A kernel trace (Windows Performance Recorder) shows which driver.".into()),
                impact: Some(("Windows CPU".into(), format!("{:.1} cores", s.system_cpu / 100.0), (s.system_cpu / 200.0).clamp(0.0, 1.0) as f32)),
                watch: Metric::SystemCpu,
            });
        }

        // 8. Duplicate dev servers left running.
        for (project, copies) in duplicate_dev_servers(s) {
            let (pids, mem, label, count) = copies;
            out.push(Finding {
                key: format!("dev:{project}"),
                level: Level::Growing,
                title: format!("{project} is running {count} copies of {label}"),
                figure: fmt_bytes(mem as f64),
                subject: format!("used by {count} copies of {label} in {project}"),
                detail: format!("{} between them. Usually left over from dev servers restarted in a new terminal.", fmt_bytes(mem as f64)),
                now: Some(Act {
                    label: "Stop older copies".into(),
                    hint: "Keeps the newest copy running.".into(),
                    run: Run::Kill(self.with_wrappers(s, &pids)),
                }),
                fix: None,
                note: None,
                impact: None,
                watch: Metric::Commit,
            });
        }

        out.retain(|f| !self.ignored.contains(&f.key));
        out.sort_by_key(|f| (f.level != Level::Over) as u8);
        out
    }

    /// The pool tag growing fastest over the current window.
    fn fastest_pool_tag(&self) -> Option<String> {
        self.history
            .pool
            .iter()
            .map(|(tag, series)| (tag, slope_per_hour(&series.window(6.0 * 3600.0))))
            .filter(|(_, (slope, cov))| *cov >= MIN_WATCH_SECS && *slope > 10.0 * 1048576.0)
            .max_by(|a, b| a.1.0.total_cmp(&b.1.0))
            .map(|(t, _)| t.clone())
    }

    /// Tags the UI wants named; the sampler thread scans driver files for them.
    pub fn wanted_tags(&self) -> Vec<String> {
        self.fastest_pool_tag().into_iter().collect()
    }

    /// The given processes, their children, and the npm/cmd wrappers that launched them.
    pub fn with_wrappers(&self, s: &Snapshot, roots: &[u32]) -> Vec<u32> {
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
        for &root in roots {
            add(root, &kids, &mut set);
            let mut cur = by_pid.get(&root).and_then(|p| by_pid.get(&p.ppid)).copied();
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
}

/// project -> (pids of the older copies, their memory, the command, total copies)
fn duplicate_dev_servers(s: &Snapshot) -> Vec<(String, (Vec<u32>, u64, String, usize))> {
    let mut groups: HashMap<(String, String), Vec<&ProcRow>> = HashMap::new();
    for p in &s.procs {
        let (Some(project), Some(cmd)) = (&p.project, &p.cmdline) else { continue };
        if !p.name.eq_ignore_ascii_case("node.exe") && !p.name.eq_ignore_ascii_case("bun.exe") && !p.name.eq_ignore_ascii_case("python.exe") {
            continue;
        }
        let short = crate::short_command(cmd);
        // Wrappers (npm, concurrently) duplicate along with what they launch; count the real servers.
        if short.starts_with("npm") || short.starts_with("concurrently") {
            continue;
        }
        groups.entry((project.clone(), short)).or_default().push(p);
    }
    let mut out: HashMap<String, (Vec<u32>, u64, String, usize)> = HashMap::new();
    for ((project, cmd), mut ps) in groups {
        if ps.len() < 2 {
            continue;
        }
        // Children of another copy in the same group are part of that copy, not a duplicate.
        let pids: HashSet<u32> = ps.iter().map(|p| p.pid).collect();
        ps.retain(|p| !pids.contains(&p.ppid));
        if ps.len() < 2 {
            continue;
        }
        ps.sort_by(|a, b| a.age_secs.total_cmp(&b.age_secs));
        let older: Vec<&&ProcRow> = ps.iter().skip(1).collect();
        let entry = out.entry(project).or_insert((vec![], 0, cmd.clone(), 0));
        if ps.len() > entry.3 {
            entry.2 = cmd;
            entry.3 = ps.len();
        }
        entry.0.extend(older.iter().map(|p| p.pid));
        entry.1 += ps.iter().map(|p| p.private).sum::<u64>();
    }
    let mut v: Vec<_> = out.into_iter().collect();
    v.sort_by(|a, b| b.1.1.cmp(&a.1.1));
    v
}
