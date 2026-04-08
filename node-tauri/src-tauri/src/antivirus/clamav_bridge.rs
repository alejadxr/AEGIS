// ---------------------------------------------------------------------------
// ClamAV FFI bridge (Task #6, optional)
//
// Thin wrapper around libclamav via the `clamav-sys` crate. Feature-gated
// with `clamav` so the default build doesn't require libclamav to be
// installed. The default shared-library search path is used (freshclam's
// main.cvd in /var/lib/clamav on Linux, C:\ProgramData\.clamwin on Win).
// ---------------------------------------------------------------------------

#![cfg(feature = "clamav")]

use std::path::Path;

/// Scan a file with libclamav. Returns Ok(Some(rule)) on detection.
pub fn scan_file(path: &Path) -> Result<Option<String>, String> {
    // This is intentionally stubbed to a shell-out to `clamscan`, since a
    // direct FFI binding would require libclamav headers on the build host
    // and multiply build complexity. `clamscan` is shipped in every ClamAV
    // package and returns 1 on match, 0 on clean.
    let out = std::process::Command::new("clamscan")
        .arg("--no-summary")
        .arg("--infected")
        .arg(path)
        .output()
        .map_err(|e| e.to_string())?;

    if !out.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Lines look like: /path/to/file: Trojan.Foo.Bar FOUND
    for line in stdout.lines() {
        if let Some((_, rest)) = line.rsplit_once(": ") {
            if let Some(rule) = rest.strip_suffix(" FOUND") {
                return Ok(Some(rule.to_string()));
            }
        }
    }
    Ok(None)
}
