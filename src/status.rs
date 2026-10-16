//! The main view. One rule: show, don't tell. Numbers, gauges and lines carry the meaning; words
//! that only need reading once live in tooltips.

use std::time::{Duration, Instant};

use gpui::{
    Animation, AnimationExt, AnyElement, AnyView, App, ClickEvent, ClipboardItem, Context, Div, FontWeight, MouseButton,
    PathBuilder, SharedString, Stateful, Window, canvas, div, ease_out_quint, point, prelude::*, px, relative, rgba, size,
};

use crate::findings::{self, Act, Finding, Run};
use crate::model::{Metric, Snapshot, fmt_age, fmt_bytes, fmt_count};
use crate::{Leakwatch, Level, Page, fmt_metric, sparkline};

// Windows 11 dark palette over acrylic, RRGGBBAA.
pub const SURFACE: u32 = 0xffffff0f;
pub const SURFACE_HOVER: u32 = 0xffffff17;
pub const SURFACE_PRESS: u32 = 0xffffff0a;
pub const STROKE: u32 = 0xffffff14;
pub const TEXT_1: u32 = 0xffffffee;
pub const TEXT_2: u32 = 0xffffffa0;
pub const TEXT_3: u32 = 0xffffff66;
pub const CRITICAL: u32 = 0xff8f86ff;
pub const CAUTION: u32 = 0xf5c451ff;
pub const DISPLAY: &str = "Segoe UI Variable Display";
pub const BODY: &str = "Segoe UI Variable Text";

const HOLD: Duration = Duration::from_millis(700);
pub const STATUS_WIDTH: f32 = 520.0;
const INNER: f32 = STATUS_WIDTH - 64.0;

fn level_color(l: Level) -> u32 {
    match l {
        Level::Over => CRITICAL,
        Level::Growing => CAUTION,
        Level::Quiet => TEXT_1,
    }
}

struct Tip(SharedString);

impl Render for Tip {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .max_w(px(300.))
            .px_3()
            .py_2()
            .rounded_md()
            .bg(rgba(0x2b2b2dff))
            .border_1()
            .border_color(rgba(STROKE))
            .font_family(BODY)
            .text_xs()
            .text_color(rgba(TEXT_1))
            .child(self.0.clone())
    }
}

/// Tooltip builder for words a person reads once and then knows.
pub fn tip(text: impl Into<SharedString>) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
    let text: SharedString = text.into();
    move |_, cx| cx.new(|_| Tip(text.clone())).into()
}

/// Fill from 0 to 1 against the point where the number becomes a problem.
fn gauge(fraction: f32, color: u32) -> Div {
    div()
        .h(px(3.))
        .w_full()
        .rounded_full()
        .bg(rgba(SURFACE_HOVER))
        .child(div().h_full().w(relative(fraction.clamp(0.015, 1.0))).rounded_full().bg(rgba(color)))
}

/// A ring that fills over the first 30 minutes of watching, then becomes a solid dot.
fn watch_ring(progress: f32) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let r = f32::from(bounds.size.width) / 2.0 - 1.5;
            let cx0 = bounds.origin.x + px(r + 1.5);
            let cy0 = bounds.origin.y + px(r + 1.5);
            let at = |a: f32| point(cx0 + px(r * a.sin()), cy0 - px(r * a.cos()));
            let radii = point(px(r), px(r));
            if progress >= 1.0 {
                let mut b = PathBuilder::fill();
                b.move_to(at(0.0));
                b.arc_to(radii, px(0.), false, true, at(std::f32::consts::PI));
                b.arc_to(radii, px(0.), false, true, at(0.0));
                if let Ok(p) = b.build() {
                    window.paint_path(p, rgba(TEXT_3));
                }
                return;
            }
            let mut track = PathBuilder::stroke(px(1.5));
            track.move_to(at(0.0));
            track.arc_to(radii, px(0.), false, true, at(std::f32::consts::PI));
            track.arc_to(radii, px(0.), false, true, at(0.0));
            if let Ok(p) = track.build() {
                window.paint_path(p, rgba(SURFACE_HOVER));
            }
            let end = progress.max(0.03) * std::f32::consts::TAU;
            let mut arc = PathBuilder::stroke(px(1.5));
            arc.move_to(at(0.0));
            arc.arc_to(radii, px(0.), end > std::f32::consts::PI, true, at(end));
            if let Ok(p) = arc.build() {
                window.paint_path(p, rgba(TEXT_2));
            }
        },
    )
    .size(px(14.))
}

impl Leakwatch {
    pub fn status_height(&self, found: &[Finding], verified: bool) -> f32 {
        let mut h = if found.is_empty() { 226.0 } else { 270.0 };
        if found.first().is_some_and(|f| f.impact.is_some()) {
            h += 30.0;
        }
        h += found.len().saturating_sub(1) as f32 * 40.0;
        if self.scripts_open {
            h += 16.0 + 40.0 * self.actions.len().max(1).div_ceil(3) as f32;
        }
        if verified {
            h += 60.0;
        }
        h
    }

    pub fn fit_window(&mut self, window: &mut Window, w: f32, h: f32) {
        let key = (w.round() as i32, h.round() as i32);
        if self.fitted != Some(key) {
            self.fitted = Some(key);
            window.resize(size(px(w), px(h)));
        }
    }

    /// Seconds of history behind the growth checks (persisted, so it survives restarts).
    pub fn watched_secs(&self) -> f64 {
        let Some(series) = self.history.system.get(&Metric::Zombies) else { return 0.0 };
        let first = series.coarse.front().or(series.fine.front()).map(|p| p.0);
        let last = series.fine.back().map(|p| p.0);
        match (first, last) {
            (Some(a), Some(b)) => b - a,
            _ => 0.0,
        }
    }

    pub fn render_status(&mut self, s: &Snapshot, window: &mut Window, cx: &mut Context<Self>) -> Div {
        let found = self.findings(s);
        self.advance_hold(&found, window);
        let verified = self.verified_row(s);
        let h = self.status_height(&found, verified.is_some());
        self.fit_window(window, STATUS_WIDTH, h);

        let focus = self.focus.as_ref().and_then(|k| found.iter().position(|f| &f.key == k)).unwrap_or(0);
        let body = if found.is_empty() {
            self.calm(s)
        } else {
            let mut col = div().flex().flex_col().gap_5().child(self.hero(&found[focus], s, cx));
            let others: Vec<&Finding> = found.iter().enumerate().filter(|(i, _)| *i != focus).map(|(_, f)| f).collect();
            if !others.is_empty() {
                let mut list = div().flex().flex_col();
                for f in others {
                    list = list.child(self.other_row(f, cx));
                }
                col = col.child(list);
            }
            col.into_any_element()
        };

        div()
            .size_full()
            .flex()
            .flex_col()
            .px_8()
            .pt_6()
            .pb_5()
            .gap_5()
            .children(verified)
            .child(div().flex_1().child(body))
            .children(self.scripts_open.then(|| self.scripts_list(cx)))
            .child(self.footer(cx))
    }

    fn ring(&self) -> Stateful<Div> {
        let watched = self.watched_secs();
        let p = (watched / findings::MIN_WATCH_SECS) as f32;
        let text = if p < 1.0 {
            format!("Watching for {}. Leaks that build up slowly show after 30 minutes.", fmt_age(watched.max(1.0)))
        } else {
            format!("Watching for {}.", fmt_age(watched))
        };
        div().id("ring").child(watch_ring(p)).tooltip(tip(text))
    }

    fn calm(&self, s: &Snapshot) -> AnyElement {
        let zombie_limit = Metric::Zombies.limit(s).unwrap_or(2000.0);
        let mem = s.mem.commit as f64 / s.mem.commit_limit.max(1) as f64;
        let stat = |id: &'static str, label: &'static str, value: String, fill: Option<f32>, color: u32, help: &'static str| {
            div()
                .id(id)
                .flex_1()
                .flex()
                .flex_col()
                .gap(px(6.))
                .child(div().font_family(BODY).text_xs().text_color(rgba(TEXT_3)).child(label))
                .child(div().font_family(DISPLAY).text_xl().font_weight(FontWeight::SEMIBOLD).text_color(rgba(TEXT_1)).child(value))
                .child(match fill {
                    Some(f) => gauge(f, color),
                    None => div().h(px(3.)),
                })
                .tooltip(tip(help))
        };
        div()
            .flex()
            .flex_col()
            .gap_6()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(div().font_family(DISPLAY).text_3xl().font_weight(FontWeight::SEMIBOLD).text_color(rgba(TEXT_1)).child("No leaks"))
                    .child(self.ring()),
            )
            .child(
                div()
                    .flex()
                    .gap_8()
                    .child(stat(
                        "stat-up",
                        "Uptime",
                        fmt_age(s.uptime as f64),
                        None,
                        TEXT_3,
                        "Time since Windows last started. Leaks add up with uptime, which is why restarting seems to fix things.",
                    ))
                    .child(stat(
                        "stat-held",
                        "Held",
                        fmt_count(s.zombies as f64),
                        Some((s.zombies as f64 / zombie_limit) as f32),
                        if s.zombies as f64 > zombie_limit { CRITICAL } else { TEXT_3 },
                        "Closed programs still kept in memory by another program. A few hundred is normal; the bar fills at 2,000.",
                    ))
                    .child(stat(
                        "stat-mem",
                        "Memory",
                        format!("{} / {}", fmt_bytes(s.mem.commit as f64).replace(" GB", ""), fmt_bytes(s.mem.commit_limit as f64)),
                        Some(mem as f32),
                        if mem > 0.85 { CAUTION } else { TEXT_3 },
                        "Memory in use out of what Windows can hand out (RAM plus page file).",
                    )),
            )
            .with_animation("calm-in", Animation::new(Duration::from_millis(220)).with_easing(ease_out_quint()), |d, t| {
                d.opacity(t).mt(px((1.0 - t) * 6.0))
            })
            .into_any_element()
    }

    fn hero(&self, f: &Finding, s: &Snapshot, cx: &mut Context<Self>) -> impl IntoElement {
        let back = self.acted.get(&f.key).is_some_and(|a| s.t - a.at > 1200.0);
        let color = level_color(f.level);
        let key = f.key.clone();
        let history = self.history.system.get(&f.watch).map(|x| x.window(7.0 * 86400.0)).unwrap_or_default();
        let explain = match &f.note {
            Some(n) => format!("{} {}", f.detail, n),
            None => f.detail.clone(),
        };

        let mut buttons = div().flex().gap_2();
        if let Some(a) = &f.now {
            buttons = buttons.child(self.action_button(f, a, true, cx));
        }
        if let Some(a) = &f.fix {
            buttons = buttons.child(self.action_button(f, a, f.now.is_none(), cx));
        }

        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_start()
                    .justify_between()
                    .child(
                        div()
                            .id(SharedString::from(format!("figure-{}", f.key)))
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .flex()
                                    .items_baseline()
                                    .gap_3()
                                    .child(
                                        div()
                                            .font_family(DISPLAY)
                                            .text_size(px(44.))
                                            .line_height(px(48.))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgba(color))
                                            .child(f.figure.clone()),
                                    )
                                    .children(back.then(|| div().font_family(BODY).text_xs().text_color(rgba(TEXT_3)).child("again"))),
                            )
                            .child(div().font_family(BODY).text_base().text_color(rgba(TEXT_1)).child(f.subject.clone()))
                            .tooltip(tip(explain)),
                    )
                    .child(
                        div()
                            .id(SharedString::from(format!("ignore-{key}")))
                            .size(px(28.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_md()
                            .cursor_pointer()
                            .font_family(BODY)
                            .text_base()
                            .text_color(rgba(TEXT_3))
                            .hover(|st| st.bg(rgba(SURFACE)).text_color(rgba(TEXT_1)))
                            .active(|st| st.bg(rgba(SURFACE_PRESS)))
                            .child("×")
                            .tooltip(tip("Ignore. No more alerts for this problem; undo on the Details page."))
                            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                                this.ignore(&key, true);
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .id(SharedString::from(format!("trend-{}", f.key)))
                    .child(sparkline(history, color, INNER, 36.))
                    .tooltip(tip("Up to the last 7 days.")),
            )
            .children(f.impact.clone().map(|(label, value, fill)| {
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(div().w(px(92.)).font_family(BODY).text_xs().text_color(rgba(TEXT_3)).child(label))
                    .child(div().flex_1().child(gauge(fill, color)))
                    .child(div().font_family(BODY).text_xs().text_color(rgba(TEXT_2)).child(value))
            }))
            .child(buttons)
            .with_animation(
                SharedString::from(format!("hero-{}", f.key)),
                Animation::new(Duration::from_millis(220)).with_easing(ease_out_quint()),
                |d, t| d.opacity(t).mt(px((1.0 - t) * 6.0)),
            )
    }

    fn other_row(&self, f: &Finding, cx: &mut Context<Self>) -> Stateful<Div> {
        let key = f.key.clone();
        div()
            .id(SharedString::from(format!("other-{}", f.key)))
            .flex()
            .items_baseline()
            .gap_3()
            .px_2()
            .mx(px(-8.))
            .py_2()
            .rounded_md()
            .cursor_pointer()
            .hover(|st| st.bg(rgba(SURFACE)))
            .active(|st| st.bg(rgba(SURFACE_PRESS)))
            .child(div().font_family(DISPLAY).text_base().font_weight(FontWeight::SEMIBOLD).text_color(rgba(level_color(f.level))).child(f.figure.clone()))
            .child(div().flex_1().min_w_0().truncate().font_family(BODY).text_sm().text_color(rgba(TEXT_2)).child(f.subject.clone()))
            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                this.focus = Some(key.clone());
                cx.notify();
            }))
    }

    /// Ending a process is held to confirm (the fill shows the hold); a service change confirms in UAC.
    fn action_button(&self, f: &Finding, act: &Act, primary: bool, cx: &mut Context<Self>) -> Stateful<Div> {
        let needs_hold = matches!(act.run, Run::Kill(_));
        let hold_key = format!("{}:{}", f.key, act.label);
        let progress = self
            .hold
            .as_ref()
            .filter(|(k, _)| *k == hold_key)
            .map(|(_, t)| (t.elapsed().as_secs_f32() / HOLD.as_secs_f32()).min(1.0))
            .unwrap_or(0.0);
        let early = self.hold_hint.as_ref().is_some_and(|(k, t)| *k == hold_key && t.elapsed().as_millis() < 1500);
        let (bg, hover, press, fg) =
            if primary { (0xffffffe8u32, 0xfffffffau32, 0xffffffccu32, 0x141414ffu32) } else { (SURFACE, SURFACE_HOVER, SURFACE_PRESS, TEXT_1) };
        let label = if early { "Hold".to_string() } else { act.label.clone() };
        let help = if needs_hold { format!("{} Press and hold.", act.hint) } else { act.hint.clone() };
        let mut b = div()
            .id(SharedString::from(format!("act-{hold_key}")))
            .relative()
            .overflow_hidden()
            .px_4()
            .py(px(7.))
            .rounded_md()
            .bg(rgba(bg))
            .cursor_pointer()
            .hover(move |st| st.bg(rgba(hover)))
            .active(move |st| st.bg(rgba(press)))
            .child(div().absolute().top_0().left_0().h_full().w(relative(progress)).bg(rgba(if primary { 0x00000026 } else { 0xffffff1a })))
            .child(div().relative().font_family(BODY).text_sm().font_weight(FontWeight::SEMIBOLD).text_color(rgba(fg)).child(label))
            .tooltip(tip(help));
        let (key, watch, act2) = (f.key.clone(), f.watch, act.clone());
        if needs_hold {
            let (hk, hk2) = (hold_key.clone(), hold_key.clone());
            b = b
                .on_mouse_down(MouseButton::Left, cx.listener(move |this, _, window, cx| {
                    this.hold = Some((hk.clone(), Instant::now()));
                    this.hold_target = Some((key.clone(), watch, act2.clone()));
                    window.request_animation_frame();
                    cx.notify();
                }))
                .on_mouse_up(MouseButton::Left, cx.listener(move |this, _, _, cx| {
                    if this.hold.as_ref().is_some_and(|(k, t)| *k == hk2 && t.elapsed() < HOLD) {
                        this.hold_hint = Some((hk2.clone(), Instant::now()));
                    }
                    this.hold = None;
                    cx.notify();
                }))
                .on_mouse_up_out(MouseButton::Left, cx.listener(|this, _, _, cx| {
                    this.hold = None;
                    cx.notify();
                }));
        } else {
            b = b.on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                this.run_act(&key, watch, &act2);
                cx.notify();
            }));
        }
        b
    }

    /// Runs a held action once the hold completes; keeps frames coming while the fill animates.
    fn advance_hold(&mut self, found: &[Finding], window: &mut Window) {
        if let Some((_, started)) = &self.hold {
            if started.elapsed() >= HOLD {
                self.hold = None;
                if let Some((key, watch, act)) = self.hold_target.take() {
                    if found.iter().any(|f| f.key == key) {
                        self.run_act(&key, watch, &act);
                    }
                }
            } else {
                window.request_animation_frame();
            }
        }
    }

    /// After an action: the before and after numbers, and the line that shows the drop.
    fn verified_row(&self, s: &Snapshot) -> Option<AnyElement> {
        let a = self.acted.values().filter(|a| s.t - a.at < 1800.0).max_by(|x, y| x.at.total_cmp(&y.at))?;
        let now = a.metric.value(s).unwrap_or(0.0);
        let dropped = now < a.before * 0.9;
        let waiting = !dropped && s.t - a.at < 120.0;
        let (mark, color) = if dropped { ("✓", TEXT_1) } else if waiting { ("…", TEXT_2) } else { ("!", CAUTION) };
        let pts = self.history.system.get(&a.metric).map(|x| x.window((s.t - a.at + 300.0).min(3600.0))).unwrap_or_default();
        let help = if dropped {
            format!("{} worked.", a.label)
        } else if waiting {
            format!("{}: waiting for the number to drop.", a.label)
        } else {
            format!("{} did not lower the number.", a.label)
        };
        Some(
            div()
                .id("verified")
                .flex()
                .items_center()
                .gap_3()
                .px_3()
                .py_2()
                .rounded_md()
                .bg(rgba(SURFACE))
                .child(div().font_family(BODY).text_sm().text_color(rgba(color)).child(mark))
                .child(
                    div()
                        .font_family(BODY)
                        .text_sm()
                        .text_color(rgba(TEXT_1))
                        .child(if waiting {
                            format!("{} → …", fmt_metric(a.metric, a.before))
                        } else {
                            format!("{} → {}", fmt_metric(a.metric, a.before), fmt_metric(a.metric, now))
                        }),
                )
                .child(div().flex_1())
                .child(sparkline(pts, if dropped { TEXT_2 } else { color }, 120., 20.))
                .tooltip(tip(help))
                .with_animation("verified-in", Animation::new(Duration::from_millis(200)).with_easing(ease_out_quint()), |d, t| d.opacity(t))
                .into_any_element(),
        )
    }

    fn scripts_list(&self, cx: &mut Context<Self>) -> Div {
        let mut grid = div().flex().flex_wrap().gap_2();
        if self.actions.is_empty() {
            grid = grid.child(div().font_family(BODY).text_xs().text_color(rgba(TEXT_3)).child("Add buttons in actions.txt (Details, Data folder)."));
        }
        for (i, a) in self.actions.iter().enumerate() {
            let (cmd, admin, label) = (a.command.clone(), a.admin, a.label.clone());
            grid = grid.child(
                div()
                    .id(SharedString::from(format!("script-{i}")))
                    .px_3()
                    .py(px(6.))
                    .rounded_md()
                    .bg(rgba(SURFACE))
                    .hover(|st| st.bg(rgba(SURFACE_HOVER)))
                    .active(|st| st.bg(rgba(SURFACE_PRESS)))
                    .cursor_pointer()
                    .font_family(BODY)
                    .text_sm()
                    .text_color(rgba(TEXT_1))
                    .child(a.label.clone())
                    .tooltip(tip(a.command.clone()))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        let ok = if admin { crate::sys::run_elevated(&cmd) } else { crate::sys::run_console(&cmd) };
                        this.flash(if ok { format!("{label} started") } else { format!("{label} cancelled") });
                        cx.notify();
                    })),
            );
        }
        grid
    }

    pub fn text_button(
        &self,
        id: impl Into<SharedString>,
        label: impl Into<SharedString>,
        cx: &mut Context<Self>,
        f: impl Fn(&mut Self, &mut Context<Self>) + 'static,
    ) -> Stateful<Div> {
        div()
            .id(id.into())
            .px_2()
            .py_1()
            .mx(px(-8.))
            .rounded_md()
            .font_family(BODY)
            .text_sm()
            .text_color(rgba(TEXT_3))
            .cursor_pointer()
            .hover(|st| st.text_color(rgba(TEXT_1)).bg(rgba(SURFACE)))
            .active(|st| st.bg(rgba(SURFACE_PRESS)))
            .child(label.into())
            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                f(this, cx);
                cx.notify();
            }))
    }

    fn footer(&self, cx: &mut Context<Self>) -> Div {
        let status = self.status.as_ref().filter(|(_, t)| t.elapsed().as_secs() < 6).map(|(m, _)| m.clone());
        div()
            .flex()
            .items_center()
            .gap_6()
            .child(self.text_button("go-details", "Details", cx, |this, _| this.page = Page::Details))
            .child(self.text_button("toggle-scripts", "Scripts", cx, |this, _| this.scripts_open = !this.scripts_open))
            .child(self.text_button("copy-report", "Copy report", cx, |this, cx| {
                let r = this.report();
                cx.write_to_clipboard(ClipboardItem::new_string(r));
                this.flash("Copied");
            }))
            .child(div().flex_1())
            .children(status.map(|m| div().font_family(BODY).text_xs().text_color(rgba(TEXT_3)).child(m)))
    }
}
