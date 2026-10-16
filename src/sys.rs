//! Raw Windows queries. Everything here works without admin rights.
//!
//! Zombie processes are process objects the kernel still keeps because some handle points at them
//! after they exited. `NtQueryObject(ObjectTypesInformation)` gives the total number of process
//! objects; subtracting the live processes from `SystemProcessInformation` leaves the zombies.
//! The system handle table then shows who holds process handles, which names the culprit.

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use std::process::Command;

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const SYSTEM_POOL_TAG_INFORMATION: u32 = 22;
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
const OBJECT_TYPES_INFORMATION: u32 = 3;
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_TERMINATE: u32 = 0x0001;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryObject(h: *mut c_void, class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryInformationProcess(h: *mut c_void, class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn OpenThread(access: u32, inherit: i32, tid: u32) -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn TerminateProcess(h: *mut c_void, code: u32) -> i32;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThreadId() -> u32;
    fn GetTickCount64() -> u64;
    fn AttachConsole(pid: u32) -> i32;
    fn K32GetPerformanceInfo(info: *mut PerformanceInfo, cb: u32) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, db: *const u16, access: u32) -> *mut c_void;
    fn EnumServicesStatusExW(
        scm: *mut c_void, level: u32, kind: u32, state: u32, buf: *mut u8, len: u32,
        needed: *mut u32, returned: *mut u32, resume: *mut u32, group: *const u16,
    ) -> i32;
    fn CloseServiceHandle(h: *mut c_void) -> i32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn ShellExecuteW(
        hwnd: *mut c_void, op: *const u16, file: *const u16, params: *const u16,
        dir: *const u16, show: i32,
    ) -> isize;
}

#[repr(C)]
#[derive(Default)]
struct PerformanceInfo {
    cb: u32,
    commit_total: usize,
    commit_limit: usize,
    commit_peak: usize,
    physical_total: usize,
    physical_available: usize,
    system_cache: usize,
    kernel_total: usize,
    kernel_paged: usize,
    kernel_nonpaged: usize,
    page_size: usize,
    handle_count: u32,
    process_count: u32,
    thread_count: u32,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Calls an Nt query that reports "buffer too small", growing the buffer until it fits.
fn query_growing(mut f: impl FnMut(*mut c_void, u32, &mut u32) -> i32, start: usize) -> Option<Vec<u8>> {
    let mut len = start;
    for _ in 0..12 {
        let mut buf = vec![0u8; len];
        let mut ret = 0u32;
        let st = f(buf.as_mut_ptr() as *mut c_void, len as u32, &mut ret);
        if st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL {
            len = (ret as usize).max(len * 2) + 64 * 1024;
            continue;
        }
        if st < 0 {
            return None;
        }
        return Some(buf);
    }
    None
}

fn rd<T: Copy>(buf: &[u8], off: usize) -> T {
    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const T) }
}

#[derive(Clone, Debug)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub create_time: i64,
    pub threads: u32,
    pub handles: u32,
    pub private: u64,
    pub working_set: u64,
    pub cpu_100ns: i64,
    pub kernel_100ns: i64,
    pub session: u32,
}

pub fn processes() -> Vec<Proc> {
    let Some(buf) = query_growing(
        |b, l, r| unsafe { NtQuerySystemInformation(SYSTEM_PROCESS_INFORMATION, b, l, r) },
        1 << 20,
    ) else {
        return vec![];
    };
    let mut out = Vec::with_capacity(512);
    let mut off = 0usize;
    loop {
        let next: u32 = rd(&buf, off);
        let name_len: u16 = rd(&buf, off + 56);
        let name_ptr: usize = rd(&buf, off + 64);
        let name = if name_ptr == 0 || name_len == 0 {
            "System Idle".to_string()
        } else {
            let s = unsafe { std::slice::from_raw_parts(name_ptr as *const u16, name_len as usize / 2) };
            String::from_utf16_lossy(s)
        };
        let user: i64 = rd(&buf, off + 40);
        let kernel: i64 = rd(&buf, off + 48);
        out.push(Proc {
            pid: rd::<usize>(&buf, off + 80) as u32,
            ppid: rd::<usize>(&buf, off + 88) as u32,
            name,
            create_time: rd(&buf, off + 32),
            threads: rd(&buf, off + 4),
            handles: rd(&buf, off + 96),
            session: rd(&buf, off + 100),
            working_set: rd::<usize>(&buf, off + 144) as u64,
            private: rd::<usize>(&buf, off + 184) as u64,
            cpu_100ns: user + kernel,
            kernel_100ns: kernel,
        });
        if next == 0 {
            break;
        }
        off += next as usize;
    }
    out
}

#[derive(Clone, Debug)]
pub struct ObjType {
    pub name: String,
    pub index: u8,
    pub objects: u32,
    pub handles: u32,
}

/// Object counts per kernel object type (Process, Thread, Event, File, ...).
pub fn object_types() -> Vec<ObjType> {
    let Some(buf) = query_growing(
        |b, l, r| unsafe { NtQueryObject(std::ptr::null_mut(), OBJECT_TYPES_INFORMATION, b, l, r) },
        64 * 1024,
    ) else {
        return vec![];
    };
    let n: u32 = rd(&buf, 0);
    let mut off = 8usize;
    let mut out = Vec::new();
    for _ in 0..n {
        if off + 104 > buf.len() {
            break;
        }
        let len: u16 = rd(&buf, off);
        let max: u16 = rd(&buf, off + 2);
        let ptr: usize = rd(&buf, off + 8);
        let name = if ptr != 0 {
            let s = unsafe { std::slice::from_raw_parts(ptr as *const u16, len as usize / 2) };
            String::from_utf16_lossy(s)
        } else {
            String::new()
        };
        out.push(ObjType {
            name,
            objects: rd(&buf, off + 16),
            handles: rd(&buf, off + 20),
            index: rd(&buf, off + 90),
        });
        off = (off + 104 + max as usize + 7) & !7;
    }
    out
}

/// Per holder pid: how many Process and Thread handles that process has open.
pub struct HandleCensus {
    pub process_handles: HashMap<u32, u32>,
    pub thread_handles: HashMap<u32, u32>,
}

pub fn handle_census(types: &[ObjType]) -> HandleCensus {
    let mut census = HandleCensus { process_handles: HashMap::new(), thread_handles: HashMap::new() };
    let mut pt = types.iter().find(|t| t.name == "Process").map(|t| t.index as u16);
    let mut tt = types.iter().find(|t| t.name == "Thread").map(|t| t.index as u16);
    // Fallback: find the type index of handles we open ourselves.
    let own_pid = unsafe { GetCurrentProcessId() };
    let hp = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, own_pid) };
    let ht = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, GetCurrentThreadId()) };
    let buf = query_growing(
        |b, l, r| unsafe { NtQuerySystemInformation(SYSTEM_EXTENDED_HANDLE_INFORMATION, b, l, r) },
        8 << 20,
    );
    if let Some(buf) = buf {
        let n: usize = rd(&buf, 0);
        let entry = |i: usize| 16 + i * 40;
        if pt.is_none() || tt.is_none() || pt == Some(0) {
            for i in 0..n {
                let o = entry(i);
                if o + 40 > buf.len() {
                    break;
                }
                let pid: usize = rd(&buf, o + 8);
                if pid as u32 != own_pid {
                    continue;
                }
                let hv: usize = rd(&buf, o + 16);
                let ty: u16 = rd(&buf, o + 30);
                if hv == hp as usize {
                    pt = Some(ty);
                }
                if hv == ht as usize {
                    tt = Some(ty);
                }
            }
        }
        for i in 0..n {
            let o = entry(i);
            if o + 40 > buf.len() {
                break;
            }
            let ty: u16 = rd(&buf, o + 30);
            let pid = rd::<usize>(&buf, o + 8) as u32;
            if Some(ty) == pt {
                *census.process_handles.entry(pid).or_default() += 1;
            } else if Some(ty) == tt {
                *census.thread_handles.entry(pid).or_default() += 1;
            }
        }
    }
    unsafe {
        if !hp.is_null() {
            CloseHandle(hp);
        }
        if !ht.is_null() {
            CloseHandle(ht);
        }
    }
    census
}

#[derive(Clone, Debug)]
pub struct PoolTag {
    pub tag: String,
    pub nonpaged: u64,
    pub paged: u64,
    pub allocs: i64,
}

pub fn pool_tags() -> Vec<PoolTag> {
    let Some(buf) = query_growing(
        |b, l, r| unsafe { NtQuerySystemInformation(SYSTEM_POOL_TAG_INFORMATION, b, l, r) },
        1 << 20,
    ) else {
        return vec![];
    };
    let n: u32 = rd(&buf, 0);
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let o = 8 + i * 40;
        if o + 40 > buf.len() {
            break;
        }
        let tag: [u8; 4] = rd(&buf, o);
        let tag: String = tag.iter().map(|&c| if c.is_ascii_graphic() || c == b' ' { c as char } else { '?' }).collect();
        let p_alloc: u32 = rd(&buf, o + 4);
        let p_free: u32 = rd(&buf, o + 8);
        let n_alloc: u32 = rd(&buf, o + 24);
        let n_free: u32 = rd(&buf, o + 28);
        out.push(PoolTag {
            tag,
            paged: rd::<usize>(&buf, o + 16) as u64,
            nonpaged: rd::<usize>(&buf, o + 32) as u64,
            allocs: (p_alloc as i64 - p_free as i64) + (n_alloc as i64 - n_free as i64),
        });
    }
    out
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Memory {
    pub commit: u64,
    pub commit_limit: u64,
    pub available: u64,
    pub physical: u64,
    pub nonpaged: u64,
    pub paged: u64,
    pub handles: u32,
    pub threads: u32,
}

pub fn memory() -> Memory {
    let mut pi = PerformanceInfo { cb: std::mem::size_of::<PerformanceInfo>() as u32, ..Default::default() };
    if unsafe { K32GetPerformanceInfo(&mut pi, pi.cb) } == 0 {
        return Memory::default();
    }
    let p = pi.page_size as u64;
    Memory {
        commit: pi.commit_total as u64 * p,
        commit_limit: pi.commit_limit as u64 * p,
        available: pi.physical_available as u64 * p,
        physical: pi.physical_total as u64 * p,
        nonpaged: pi.kernel_nonpaged as u64 * p,
        paged: pi.kernel_paged as u64 * p,
        handles: pi.handle_count,
        threads: pi.thread_count,
    }
}

/// Lets a windowed app print to the console it was started from.
pub fn attach_parent_console() {
    unsafe { AttachConsole(u32::MAX) };
}

pub fn uptime_secs() -> u64 {
    unsafe { GetTickCount64() / 1000 }
}

pub fn command_line(pid: u32) -> Option<String> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let buf = query_growing(
        |b, l, r| unsafe { NtQueryInformationProcess(h, PROCESS_COMMAND_LINE_INFORMATION, b, l, r) },
        4096,
    );
    unsafe { CloseHandle(h) };
    let buf = buf?;
    let len: u16 = rd(&buf, 0);
    let ptr: usize = rd(&buf, 8);
    if ptr == 0 {
        return None;
    }
    let s = unsafe { std::slice::from_raw_parts(ptr as *const u16, len as usize / 2) };
    Some(String::from_utf16_lossy(s))
}

pub fn kill(pid: u32) -> bool {
    let h = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if h.is_null() {
        return false;
    }
    let ok = unsafe { TerminateProcess(h, 1) } != 0;
    unsafe { CloseHandle(h) };
    ok
}

#[derive(Clone, Debug)]
pub struct Service {
    pub name: String,
    pub display: String,
    pub accepts_stop: bool,
}

fn read_wstr(ptr: usize) -> String {
    if ptr == 0 {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *(ptr as *const u16).add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr as *const u16, len))
    }
}

/// Running Win32 services keyed by host pid.
pub fn services_by_pid() -> HashMap<u32, Vec<Service>> {
    let mut map: HashMap<u32, Vec<Service>> = HashMap::new();
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), 0x0004);
        if scm.is_null() {
            return map;
        }
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let ok = EnumServicesStatusExW(
                scm, 0, 0x30, 0x1, buf.as_mut_ptr(), buf.len() as u32,
                &mut needed, &mut count, &mut resume, std::ptr::null(),
            );
            for i in 0..count as usize {
                let o = i * 56;
                let name_ptr: usize = rd(&buf, o);
                let pid: u32 = rd(&buf, o + 16 + 28);
                let accepts_stop = rd::<u32>(&buf, o + 16 + 8) & 0x1 != 0;
                if pid == 0 || name_ptr == 0 {
                    continue;
                }
                map.entry(pid).or_default().push(Service {
                    name: read_wstr(name_ptr),
                    display: read_wstr(rd::<usize>(&buf, o + 8)),
                    accepts_stop,
                });
            }
            if ok != 0 || resume == 0 {
                break;
            }
            if needed as usize > buf.len() {
                buf.resize(needed as usize, 0);
            }
        }
        CloseServiceHandle(scm);
    }
    map
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Gpu {
    pub temp_c: f64,
    pub power_w: f64,
    pub mem_used_mb: f64,
    pub mem_total_mb: f64,
    pub util: f64,
}

pub fn nvidia() -> Option<Gpu> {
    let out = Command::new("nvidia-smi")
        .args([
            "--query-gpu=temperature.gpu,power.draw,memory.used,memory.total,utilization.gpu",
            "--format=csv,noheader,nounits",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let v: Vec<f64> = s.lines().next()?.split(',').map(|x| x.trim().parse().unwrap_or(0.0)).collect();
    if v.len() < 5 {
        return None;
    }
    Some(Gpu { temp_c: v[0], power_w: v[1], mem_used_mb: v[2], mem_total_mb: v[3], util: v[4] })
}

/// Opens an elevated PowerShell window (UAC prompt) running `command`.
pub fn run_elevated(command: &str) -> bool {
    let params = format!("-NoExit -NoProfile -ExecutionPolicy Bypass -Command \"{}\"", command.replace('"', "\\\""));
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(), wide("runas").as_ptr(), wide("powershell.exe").as_ptr(),
            wide(&params).as_ptr(), std::ptr::null(), 1,
        )
    };
    r > 32
}

/// Opens a normal PowerShell console running `command`.
pub fn run_console(command: &str) -> bool {
    Command::new("powershell.exe")
        .args(["-NoExit", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command])
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .is_ok()
}

/// Windows toast through PowerShell's registered app id, so no installer or AUMID is needed.
pub fn toast(title: &str, body: &str) {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('\'', "''");
    let script = format!(
        "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]>$null;\
         [Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]>$null;\
         $x=New-Object Windows.Data.Xml.Dom.XmlDocument;\
         $x.LoadXml('<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual></toast>');\
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($x))",
        esc(title),
        esc(body)
    );
    let _ = Command::new("powershell.exe")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

/// Opens a file, folder, URL or settings page the way Explorer would.
pub fn open(target: &str) {
    let _ = Command::new("cmd").args(["/c", "start", "", target]).creation_flags(CREATE_NO_WINDOW).spawn();
}

/// Driver files that contain a pool tag's four bytes, the way poolmon finds a tag's owner.
pub fn drivers_with_tag(tag: &str) -> Vec<String> {
    let needle = tag.as_bytes();
    if needle.len() != 4 {
        return vec![];
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(format!(r"{root}\System32\drivers"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("sys")))
        .collect();
    files.push(format!(r"{root}\System32\ntoskrnl.exe").into());
    let mut hits = vec![];
    for f in files {
        let Ok(bytes) = std::fs::read(&f) else { continue };
        if bytes.windows(4).any(|w| w == needle) {
            hits.push(f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
        }
    }
    hits
}
