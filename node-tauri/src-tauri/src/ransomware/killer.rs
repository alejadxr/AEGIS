// ---------------------------------------------------------------------------
// Process terminator (Task #2)
//
// Walks a process tree and kills every descendant. Uses TerminateProcess on
// Windows (via the `windows` crate) and SIGKILL on Linux (via `nix`), with a
// sysinfo fallback on any other target.
// ---------------------------------------------------------------------------

use std::collections::{HashMap, HashSet, VecDeque};
use sysinfo::{Pid, System};

#[derive(Debug, Clone)]
pub struct KillResult {
    pub killed_pids: Vec<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
}

/// Terminate the given PID and every descendant process.
pub fn terminate_process_tree(root_pid: u32) -> Result<KillResult, String> {
    let mut sys = System::new_all();
    sys.refresh_all();

    // Build a parent -> children map
    let mut children_of: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, proc_) in sys.processes() {
        if let Some(ppid) = proc_.parent() {
            children_of
                .entry(ppid.as_u32())
                .or_default()
                .push(pid.as_u32());
        }
    }

    // BFS from root_pid to collect the whole tree
    let mut to_kill: Vec<u32> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();
    let mut queue: VecDeque<u32> = VecDeque::from([root_pid]);
    while let Some(pid) = queue.pop_front() {
        if !seen.insert(pid) {
            continue;
        }
        to_kill.push(pid);
        if let Some(kids) = children_of.get(&pid) {
            for k in kids {
                queue.push_back(*k);
            }
        }
    }

    // Kill children first, then root, so the root can't re-spawn them.
    to_kill.reverse();

    // Capture identity of the root process before we kill it
    let (process_name, process_path) = sys
        .process(Pid::from_u32(root_pid))
        .map(|p| {
            (
                Some(p.name().to_string_lossy().to_string()),
                p.exe().map(|e| e.to_string_lossy().to_string()),
            )
        })
        .unwrap_or((None, None));

    let mut killed = Vec::with_capacity(to_kill.len());
    for pid in to_kill {
        if kill_pid(pid) {
            killed.push(pid);
        }
    }

    Ok(KillResult {
        killed_pids: killed,
        process_name,
        process_path,
    })
}

/// Platform-specific kill.
fn kill_pid(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        kill_pid_windows(pid)
    }
    #[cfg(target_os = "linux")]
    {
        kill_pid_linux(pid)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        kill_pid_fallback(pid)
    }
}

#[cfg(target_os = "windows")]
fn kill_pid_windows(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_TERMINATE,
    };

    unsafe {
        match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(h) if h != HANDLE(std::ptr::null_mut()) => {
                let ok = TerminateProcess(h, 1).is_ok();
                let _ = CloseHandle(h);
                if !ok {
                    log::warn!("[killer] TerminateProcess({}) failed", pid);
                }
                ok
            }
            Ok(_) => {
                log::warn!("[killer] OpenProcess({}) returned null", pid);
                false
            }
            Err(e) => {
                log::warn!("[killer] OpenProcess({}) failed: {:?}", pid, e);
                false
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn kill_pid_linux(pid: u32) -> bool {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid as NixPid;
    match kill(NixPid::from_raw(pid as i32), Signal::SIGKILL) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("[killer] kill({}, SIGKILL) failed: {}", pid, e);
            false
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn kill_pid_fallback(pid: u32) -> bool {
    // sysinfo fallback (macOS etc.)
    let mut sys = System::new_all();
    sys.refresh_all();
    if let Some(p) = sys.process(Pid::from_u32(pid)) {
        p.kill()
    } else {
        false
    }
}
