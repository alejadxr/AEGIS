//! Command line, run mode and data-location selection.
//!
//! The same binary runs as a GUI (Tauri window + tray), as a headless sensor
//! (no window, no tray) or as a Windows service. Everything that depends on
//! that choice hangs off the single `RunMode` set once at startup.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// What the process was asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Gui,
    Headless,
    /// Entered by the Windows Service Control Manager.
    Service,
    InstallService,
    UninstallService,
}

/// How the sensor is hosted. Decides where data lives and whose profile the
/// ransomware canaries go into. Set once, at startup, by `set_run_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Gui,
    Headless,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Service,
}

static RUN_MODE: OnceLock<RunMode> = OnceLock::new();

/// The one switch. Call once, before any config/log path is resolved.
pub fn set_run_mode(mode: RunMode) {
    let _ = RUN_MODE.set(mode);
}

pub fn run_mode() -> RunMode {
    RUN_MODE.get().copied().unwrap_or(RunMode::Gui)
}

/// True when the process runs as the Windows service (LocalSystem).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn is_service() -> bool {
    cfg!(target_os = "windows") && run_mode() == RunMode::Service
}

/// Parse the process arguments (without argv[0]). `env_headless` is the value
/// of `AEGIS_NODE_HEADLESS`. Explicit service flags win over the env var.
/// Unknown arguments are ignored so the GUI keeps whatever Tauri passes it.
pub fn parse_args<I, S>(args: I, env_headless: Option<&str>) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut cmd = None;
    for a in args {
        match a.as_ref() {
            "--service" => return Command::Service,
            "--install-service" => return Command::InstallService,
            "--uninstall-service" => return Command::UninstallService,
            "--headless" => cmd = Some(Command::Headless),
            _ => {}
        }
    }
    if let Some(c) = cmd {
        return c;
    }
    match env_headless.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) if v == "1" || v == "true" || v == "yes" => Command::Headless,
        _ => Command::Gui,
    }
}

/// Environment values that decide the data directory.
#[derive(Debug, Default, Clone)]
pub struct DirEnv {
    pub appdata: Option<String>,
    pub program_data: Option<String>,
    pub home: Option<String>,
}

impl DirEnv {
    pub fn from_process() -> Self {
        Self {
            appdata: std::env::var("APPDATA").ok(),
            program_data: std::env::var("ProgramData").ok(),
            home: std::env::var("HOME").ok(),
        }
    }
}

/// Pure data-directory selection.
///
/// Windows GUI: `%APPDATA%\aegis-node` (per user).
/// Windows headless/service: `%ProgramData%\aegis-node`, because a LocalSystem
/// service's `%APPDATA%` is the systemprofile.
/// Unix (any mode): `$HOME/.config/aegis-node`.
pub fn data_dir_for(mode: RunMode, windows: bool, env: &DirEnv) -> PathBuf {
    if windows {
        let base = match mode {
            RunMode::Gui => env.appdata.as_deref(),
            RunMode::Headless | RunMode::Service => env
                .program_data
                .as_deref()
                .or(Some("C:\\ProgramData")),
        };
        if let Some(b) = base {
            return PathBuf::from(b).join("aegis-node");
        }
    } else if let Some(home) = env.home.as_deref() {
        return PathBuf::from(home).join(".config").join("aegis-node");
    }
    PathBuf::from(".").join("aegis-node")
}

/// Data directory for the current process.
pub fn data_dir() -> PathBuf {
    data_dir_for(run_mode(), cfg!(target_os = "windows"), &DirEnv::from_process())
}

// ---------------------------------------------------------------------------
// User profile enumeration (service mode canaries)
// ---------------------------------------------------------------------------

/// Folders under `C:\Users` that are not real user profiles.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const NON_PROFILE_DIRS: [&str; 4] = ["default", "default user", "public", "all users"];

/// Real interactive profiles among the entries of the Users directory.
/// Pure over names; the caller still checks the folders exist.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn real_profile_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    names
        .into_iter()
        .filter(|n| {
            let l = n.to_ascii_lowercase();
            !NON_PROFILE_DIRS.contains(&l.as_str())
                && !l.starts_with("defaultapppool")
                && l != "desktop.ini"
        })
        .collect()
}

/// Real profile directories under `%SystemDrive%\Users` (service mode).
#[cfg(target_os = "windows")]
pub fn service_profile_roots() -> Vec<PathBuf> {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let users = PathBuf::from(format!("{}\\Users", drive));
    let names: Vec<String> = match std::fs::read_dir(&users) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(e) => {
            log::warn!("cannot list {:?}: {}", users, e);
            return Vec::new();
        }
    };
    real_profile_names(names.iter().map(String::as_str))
        .into_iter()
        .map(|n| users.join(n))
        .collect()
}

/// Folders the antivirus watches inside one Windows profile (same as the GUI).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn av_watch_paths_for_profile(profile: &Path) -> Vec<PathBuf> {
    vec![
        profile.join("Downloads"),
        profile.join("Documents"),
        profile.join("Desktop"),
        profile.join("AppData").join("Local").join("Temp"),
    ]
}

/// Windows store directory (quarantine, hash cache).
/// Service: `<data_dir>/<service_name>` (inherits the SYSTEM+Admins ACL).
/// GUI: `%LOCALAPPDATA%\aegis-node\<gui_name>`; `None` when it is unset.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn windows_store_dir(
    service: bool,
    data_dir: &Path,
    local_app_data: Option<&str>,
    gui_name: &str,
    service_name: &str,
) -> Option<PathBuf> {
    if service {
        Some(data_dir.join(service_name))
    } else {
        local_app_data.map(|l| PathBuf::from(l).join("aegis-node").join(gui_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_select_command() {
        let none: [&str; 0] = [];
        assert_eq!(parse_args(none, None), Command::Gui);
        assert_eq!(parse_args(["--headless"], None), Command::Headless);
        assert_eq!(parse_args(["--service"], None), Command::Service);
        assert_eq!(parse_args(["--install-service"], None), Command::InstallService);
        assert_eq!(parse_args(["--uninstall-service"], None), Command::UninstallService);
        assert_eq!(parse_args(["--unknown", "x"], None), Command::Gui);
    }

    #[test]
    fn env_enables_headless_but_service_flags_win() {
        let none: [&str; 0] = [];
        assert_eq!(parse_args(none, Some("1")), Command::Headless);
        assert_eq!(parse_args(none, Some("TRUE")), Command::Headless);
        assert_eq!(parse_args(none, Some("0")), Command::Gui);
        assert_eq!(parse_args(none, Some("")), Command::Gui);
        assert_eq!(parse_args(["--service"], Some("1")), Command::Service);
        assert_eq!(parse_args(["--install-service"], Some("1")), Command::InstallService);
    }

    fn env() -> DirEnv {
        DirEnv {
            appdata: Some("C:\\Users\\a\\AppData\\Roaming".into()),
            program_data: Some("C:\\ProgramData".into()),
            home: Some("/home/a".into()),
        }
    }

    #[test]
    fn windows_gui_uses_appdata() {
        let d = data_dir_for(RunMode::Gui, true, &env());
        assert_eq!(d, PathBuf::from("C:\\Users\\a\\AppData\\Roaming").join("aegis-node"));
    }

    #[test]
    fn windows_headless_and_service_use_programdata() {
        for m in [RunMode::Headless, RunMode::Service] {
            let d = data_dir_for(m, true, &env());
            assert_eq!(d, PathBuf::from("C:\\ProgramData").join("aegis-node"));
        }
        let mut e = env();
        e.program_data = None;
        assert_eq!(
            data_dir_for(RunMode::Service, true, &e),
            PathBuf::from("C:\\ProgramData").join("aegis-node")
        );
    }

    #[test]
    fn unix_paths_do_not_depend_on_mode() {
        for m in [RunMode::Gui, RunMode::Headless, RunMode::Service] {
            assert_eq!(
                data_dir_for(m, false, &env()),
                PathBuf::from("/home/a/.config/aegis-node")
            );
        }
        assert_eq!(
            data_dir_for(RunMode::Gui, false, &DirEnv::default()),
            PathBuf::from("./aegis-node")
        );
    }

    #[test]
    fn profile_filter_drops_system_dirs() {
        let names = ["Default", "Default User", "Public", "All Users", "alice", "Bob", "desktop.ini"];
        assert_eq!(real_profile_names(names), vec!["alice", "Bob"]);
        assert!(real_profile_names(["DEFAULT", "public"]).is_empty());
    }

    #[test]
    fn av_watch_paths_match_gui_set() {
        let p = av_watch_paths_for_profile(Path::new("P"));
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], Path::new("P").join("Downloads"));
        assert_eq!(p[3], Path::new("P").join("AppData").join("Local").join("Temp"));
    }

    #[test]
    fn windows_store_dir_selection() {
        let dd = Path::new("D");
        assert_eq!(
            windows_store_dir(true, dd, Some("L"), "quarantine", "quarantine"),
            Some(dd.join("quarantine"))
        );
        assert_eq!(
            windows_store_dir(true, dd, None, "hash_cache", "cache"),
            Some(dd.join("cache"))
        );
        assert_eq!(
            windows_store_dir(false, dd, Some("L"), "hash_cache", "cache"),
            Some(Path::new("L").join("aegis-node").join("hash_cache"))
        );
        assert_eq!(windows_store_dir(false, dd, None, "x", "y"), None);
    }
}
