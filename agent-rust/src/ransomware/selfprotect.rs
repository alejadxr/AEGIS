//! Agent self-protection hardening — Phase R-E
//!
//! Best-effort hardening to prevent an attacker from killing the AEGIS agent:
//!
//! - Linux: `prctl(PR_SET_DUMPABLE, 0)` via `nix`; optional cgroup isolation.
//! - macOS: Logs that `EndpointSecurity` entitlement is required for full
//!   protection (codesigning requirement prevents in-process hardening).
//! - Windows: `SetProcessMitigationPolicy` (signed-DLL only) via the `windows`
//!   crate; `NtSetInformationProcess` CriticalProcess registration
//!   (requires admin — stubbed with a log if privileges are absent).
//!
//! Public API: [`enable_self_protection`] → [`ProtectionLevel`].

use serde::{Deserialize, Serialize};

/// The level of protection successfully enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionLevel {
    /// No protection could be applied.
    None,
    /// Some hardening was applied, but not all available measures succeeded.
    Partial,
    /// All available hardening for this platform was applied successfully.
    Full,
}

/// Error type for self-protection failures (non-fatal — callers log and continue).
#[derive(Debug, thiserror::Error)]
pub enum SelfProtectError {
    #[error("platform API error: {0}")]
    Platform(String),
    #[error("insufficient privileges for full hardening")]
    InsufficientPrivileges,
}

/// Enable all available self-protection measures for the current platform.
/// Returns the achieved [`ProtectionLevel`]. Errors are advisory — the caller
/// should log and continue even if protection is partial.
pub fn enable_self_protection() -> Result<ProtectionLevel, SelfProtectError> {
    enable_platform_protection()
}

// ── Linux ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn enable_platform_protection() -> Result<ProtectionLevel, SelfProtectError> {
    use nix::sys::prctl;

    let mut achieved = ProtectionLevel::None;

    // Disable core dumps to prevent memory inspection.
    match prctl::set_dumpable(false) {
        Ok(()) => {
            log::info!("[selfprotect] prctl(PR_SET_DUMPABLE, 0) — core dumps disabled");
            achieved = ProtectionLevel::Partial;
        }
        Err(e) => {
            log::warn!("[selfprotect] prctl failed: {}", e);
        }
    }

    // Attempt cgroup isolation (best-effort; requires cgroup v2 mounted).
    match try_cgroup_isolation() {
        Ok(()) => {
            log::info!("[selfprotect] cgroup isolation applied");
            achieved = ProtectionLevel::Full;
        }
        Err(e) => {
            log::warn!("[selfprotect] cgroup isolation skipped: {}", e);
        }
    }

    Ok(achieved)
}

#[cfg(target_os = "linux")]
fn try_cgroup_isolation() -> Result<(), SelfProtectError> {
    use std::fs;
    use std::io::Write;

    let pid = std::process::id();
    let cgroup_path = format!("/sys/fs/cgroup/aegis-agent");

    // Create a dedicated cgroup for the agent.
    fs::create_dir_all(&cgroup_path).map_err(|e| SelfProtectError::Platform(e.to_string()))?;

    // Write our PID into the cgroup.
    let procs_path = format!("{}/cgroup.procs", cgroup_path);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(&procs_path)
        .map_err(|e| SelfProtectError::Platform(e.to_string()))?;
    write!(f, "{}", pid).map_err(|e| SelfProtectError::Platform(e.to_string()))?;

    Ok(())
}

// ── macOS ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn enable_platform_protection() -> Result<ProtectionLevel, SelfProtectError> {
    // Full hardening on macOS requires the binary to be signed with the
    // `com.apple.developer.endpoint-security.client` entitlement and loaded
    // as a system extension — neither of which can be done at runtime.
    log::info!(
        "[selfprotect] macOS: EndpointSecurity entitlement required for full protection. \
         Sign the binary with com.apple.developer.endpoint-security.client and deploy \
         as a System Extension to prevent process termination by unprivileged attackers."
    );
    Ok(ProtectionLevel::None)
}

// ── Windows ────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn enable_platform_protection() -> Result<ProtectionLevel, SelfProtectError> {
    let level = apply_windows_mitigations();
    Ok(level)
}

#[cfg(target_os = "windows")]
fn apply_windows_mitigations() -> ProtectionLevel {
    use windows::Win32::System::Threading::{
        SetProcessMitigationPolicy,
        ProcessSignaturePolicy,
    };

    let mut achieved = ProtectionLevel::None;

    // PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY layout:
    // a single DWORD bitfield. Bit 0 = MicrosoftSignedOnly.
    // We define it inline as a u32 to avoid windows-crate version skew.
    let policy: u32 = 1; // MicrosoftSignedOnly = 1

    let result = unsafe {
        SetProcessMitigationPolicy(
            ProcessSignaturePolicy,
            &policy as *const u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>(),
        )
    };

    match result {
        Ok(()) => {
            log::info!("[selfprotect] Windows: signed-DLL-only mitigation applied");
            achieved = ProtectionLevel::Partial;
        }
        Err(e) => {
            log::warn!("[selfprotect] Windows: SetProcessMitigationPolicy failed: {e}");
        }
    }

    // NtSetInformationProcess CriticalProcess — requires admin + special care.
    // Marking as critical causes BSOD if terminated, which is a last resort.
    // Stub: log intent only; real activation requires explicit operator consent.
    log::info!(
        "[selfprotect] Windows: NtSetInformationProcess(CriticalProcess) intentionally \
         not activated — requires admin and causes BSOD on termination. \
         Enable manually for hardened deployments."
    );

    achieved
}

// ── Fallback (other platforms) ─────────────────────────────────────────────

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn enable_platform_protection() -> Result<ProtectionLevel, SelfProtectError> {
    log::warn!("[selfprotect] no hardening available on this platform");
    Ok(ProtectionLevel::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_level_serde_round_trip() {
        for level in [ProtectionLevel::None, ProtectionLevel::Partial, ProtectionLevel::Full] {
            let json = serde_json::to_string(&level).unwrap();
            let back: ProtectionLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(back, level);
        }
    }

    #[test]
    fn enable_self_protection_returns_ok() {
        // Should not panic on any platform.
        let result = enable_self_protection();
        assert!(result.is_ok(), "self protection returned Err: {:?}", result.err());
    }
}
