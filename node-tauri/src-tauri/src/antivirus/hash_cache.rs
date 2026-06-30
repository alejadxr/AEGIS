// ---------------------------------------------------------------------------
// SHA256 reputation cache (Task #6)
//
// Backed by `sled` (feature-gated; falls back to an in-memory HashMap on
// targets where sled isn't available or the feature is off). Lookups are
// cheap (<10us) and drive the on-access scanner so we only invoke YARA /
// ClamAV on unknown hashes.
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

/// Reputation status for a known SHA256.
#[derive(Debug, Clone)]
pub enum Status {
    Known,          // confirmed clean during a prior scan
    Bad(String),    // confirmed malicious, with rule name
}

#[cfg(feature = "sled")]
mod sled_backend {
    use super::*;

    pub struct Inner {
        db: sled::Db,
    }

    impl Inner {
        pub fn open(path: PathBuf) -> Result<Self, String> {
            let db = sled::open(path).map_err(|e| e.to_string())?;
            Ok(Self { db })
        }

        pub fn lookup(&self, sha: &str) -> Option<Status> {
            let key = sha.as_bytes();
            let v = self.db.get(key).ok().flatten()?;
            let s = String::from_utf8_lossy(&v).to_string();
            if let Some(rule) = s.strip_prefix("BAD:") {
                Some(Status::Bad(rule.to_string()))
            } else if s == "GOOD" {
                Some(Status::Known)
            } else {
                None
            }
        }

        pub fn mark_good(&self, sha: &str) {
            let _ = self.db.insert(sha.as_bytes(), b"GOOD");
        }

        pub fn mark_bad(&self, sha: &str, rule: &str) {
            let _ = self.db.insert(sha.as_bytes(), format!("BAD:{}", rule).as_bytes());
        }
    }
}

mod mem_backend {
    use super::*;

    #[derive(Debug)]
    pub struct Inner {
        map: RwLock<HashMap<String, Status>>,
    }

    impl Inner {
        pub fn new() -> Self {
            Self {
                map: RwLock::new(HashMap::new()),
            }
        }

        pub fn lookup(&self, sha: &str) -> Option<Status> {
            self.map.read().ok()?.get(sha).cloned()
        }

        pub fn mark_good(&self, sha: &str) {
            if let Ok(mut m) = self.map.write() {
                m.insert(sha.to_string(), Status::Known);
            }
        }

        pub fn mark_bad(&self, sha: &str, rule: &str) {
            if let Ok(mut m) = self.map.write() {
                m.insert(sha.to_string(), Status::Bad(rule.to_string()));
            }
        }
    }
}

#[derive(Debug)]
pub struct HashCache {
    mem: mem_backend::Inner,
    #[cfg(feature = "sled")]
    sled: Option<sled_backend::Inner>,
}

impl HashCache {
    pub fn open() -> Result<Self, String> {
        #[cfg(feature = "sled")]
        {
            let path = Self::db_path();
            let sled = match sled_backend::Inner::open(path.clone()) {
                Ok(s) => Some(s),
                Err(e) => {
                    log::warn!("[av] sled open failed at {:?}: {}; using memory cache", path, e);
                    None
                }
            };
            return Ok(Self {
                mem: mem_backend::Inner::new(),
                sled,
            });
        }
        #[cfg(not(feature = "sled"))]
        {
            Ok(Self {
                mem: mem_backend::Inner::new(),
            })
        }
    }

    #[cfg(feature = "sled")]
    fn db_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
                return PathBuf::from(appdata).join("aegis-node").join("hash_cache");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".aegis").join("hash_cache");
        }
        PathBuf::from(".").join("aegis-hash-cache")
    }

    pub fn lookup(&self, sha: &str) -> Option<Status> {
        if let Some(v) = self.mem.lookup(sha) {
            return Some(v);
        }
        #[cfg(feature = "sled")]
        if let Some(sled) = &self.sled {
            return sled.lookup(sha);
        }
        None
    }

    pub fn mark_good(&mut self, sha: &str) {
        self.mem.mark_good(sha);
        #[cfg(feature = "sled")]
        if let Some(sled) = &self.sled {
            sled.mark_good(sha);
        }
    }

    pub fn mark_bad(&mut self, sha: &str, rule: &str) {
        self.mem.mark_bad(sha, rule);
        #[cfg(feature = "sled")]
        if let Some(sled) = &self.sled {
            sled.mark_bad(sha, rule);
        }
    }
}
