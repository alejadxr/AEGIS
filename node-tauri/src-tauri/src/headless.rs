//! Headless sensor host: no Tauri builder, no WebView, no tray.
//!
//! Used by `--headless` and by the Windows service. It owns a tokio
//! multi-thread runtime, a file logger and the data directory, then runs the
//! very same `start_sensor` the GUI runs.

use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

use crate::cli;
use crate::{start_sensor, NodeState, Notifier};

const LOG_FILE: &str = "aegis-node.log";
/// Rotate to `aegis-node.log.1` past this size.
const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// File logger (tauri_plugin_log needs an App, which headless does not have)
// ---------------------------------------------------------------------------

struct FileLogger {
    inner: StdMutex<LogSink>,
}

struct LogSink {
    file: File,
    path: PathBuf,
    written: u64,
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {:<5} [{}] {}\n",
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            record.level(),
            record.target(),
            record.args()
        );
        // Best effort: a console is attached only when run from a terminal.
        let _ = std::io::stderr().write_all(line.as_bytes());
        if let Ok(mut sink) = self.inner.lock() {
            if sink.written >= LOG_MAX_BYTES {
                let rotated = sink.path.with_extension("log.1");
                let _ = std::fs::rename(&sink.path, &rotated);
                if let Ok(f) = OpenOptions::new().create(true).append(true).open(&sink.path) {
                    sink.file = f;
                    sink.written = 0;
                }
            }
            if sink.file.write_all(line.as_bytes()).is_ok() {
                sink.written += line.len() as u64;
            }
        }
    }

    fn flush(&self) {
        if let Ok(mut sink) = self.inner.lock() {
            let _ = sink.file.flush();
        }
    }
}

/// Install the file logger at `<data_dir>/logs/aegis-node.log`.
/// `AEGIS_NODE_LOG` (error|warn|info|debug|trace) overrides the level (info).
fn init_logger(data_dir: &Path) -> Result<PathBuf, String> {
    let dir = data_dir.join("logs");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {:?}: {}", dir, e))?;
    let path = dir.join(LOG_FILE);
    let written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open {:?}: {}", path, e))?;
    let level = std::env::var("AEGIS_NODE_LOG")
        .ok()
        .and_then(|v| v.trim().parse::<log::LevelFilter>().ok())
        .unwrap_or(log::LevelFilter::Info);
    let logger = FileLogger {
        inner: StdMutex::new(LogSink { file, path: path.clone(), written }),
    };
    log::set_boxed_logger(Box::new(logger)).map_err(|e| e.to_string())?;
    log::set_max_level(level);
    Ok(path)
}

// ---------------------------------------------------------------------------
// Data directory
// ---------------------------------------------------------------------------

/// Create the data dir; on Windows restrict it to SYSTEM and Administrators
/// (it holds the node token). Unix paths and modes are left as they were.
fn prepare_data_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {:?}: {}", dir, e))?;
    #[cfg(target_os = "windows")]
    restrict_to_system_and_admins(dir);
    Ok(())
}

/// Drop inherited ACEs and grant full control to SYSTEM (S-1-5-18) and
/// BUILTIN\Administrators (S-1-5-32-544) only. Well-known SIDs, so this is
/// locale independent. Failure is logged, not fatal: the dir then keeps the
/// ProgramData default, which we did not widen.
#[cfg(target_os = "windows")]
fn restrict_to_system_and_admins(dir: &Path) {
    let out = crate::hidden_command("icacls")
        .arg(dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => eprintln!(
            "warning: could not restrict {:?}: icacls exited {:?}",
            dir,
            o.status.code()
        ),
        Err(e) => eprintln!("warning: could not restrict {:?}: {}", dir, e),
    }
}

// ---------------------------------------------------------------------------
// Sensor host
// ---------------------------------------------------------------------------

/// Run the sensor without any UI until `shutdown` resolves.
///
/// The run mode must already be set. Blocks the calling thread.
pub fn run_sensor<F: Future<Output = ()>>(shutdown: F) -> Result<(), String> {
    let dir = cli::data_dir();
    prepare_data_dir(&dir)?;
    let log_path = init_logger(&dir)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("aegis-node-worker")
        .build()
        .map_err(|e| format!("tokio runtime: {}", e))?;
    // The sensor loops spawn through tauri::async_runtime; point it at ours
    // so no Tauri app (and no window) is needed.
    tauri::async_runtime::set(rt.handle().clone());

    log::info!(
        "AEGIS Node {} starting headless ({:?}), data dir {:?}, log {:?}",
        env!("CARGO_PKG_VERSION"),
        cli::run_mode(),
        dir,
        log_path
    );

    let state = Arc::new(Mutex::new(NodeState::new()));
    start_sensor(state, Notifier::none());

    rt.block_on(shutdown);
    log::info!("AEGIS Node shutting down");
    log::logger().flush();
    rt.shutdown_timeout(std::time::Duration::from_secs(3));
    Ok(())
}

/// `--headless`: run until Ctrl-C (or SIGTERM on unix).
pub fn run_headless() -> Result<(), String> {
    cli::set_run_mode(cli::RunMode::Headless);
    run_sensor(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            match signal(SignalKind::terminate()) {
                Ok(mut term) => {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = term.recv() => {}
                    }
                }
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    })
}
