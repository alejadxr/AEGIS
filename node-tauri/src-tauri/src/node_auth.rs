// ---------------------------------------------------------------------------
// Node -> backend authentication header (single seam for every HTTP call)
//
// The backend's node-facing routes (/nodes/*) authenticate with the shared
// secret AEGIS_NODE_SECRET, presented as `X-AEGIS-Node-Auth`
// (backend/app/api/nodes.py::_verify_node_secret). The agent reads the same
// value from its own environment at call time; nothing is compiled in, and
// the value is never logged. When it is unset no header is sent, which is
// what a backend running in compat mode (no secret configured) expects.
//
// The telemetry upload routes (/edr/events, /agents/events,
// /antivirus/detections) instead take a PER-NODE token, minted by the backend
// at enrollment and sent as `X-AEGIS-Node-Token` next to `X-AEGIS-Node-Id`.
// The token lives here (not in NodeConfig, which is serialized to the UI and
// derives Debug) and is attached only by `upload_headers()`.
// ---------------------------------------------------------------------------

use std::sync::Mutex;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

pub const NODE_AUTH_HEADER: &str = "X-AEGIS-Node-Auth";
pub const NODE_TOKEN_HEADER: &str = "X-AEGIS-Node-Token";
pub const NODE_ID_HEADER: &str = "X-AEGIS-Node-Id";
const SECRET_ENV: &str = "AEGIS_NODE_SECRET";

/// A credential that never prints itself: Debug is redacted, serde is
/// transparent so it round-trips as a plain string in the config file.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// (node_id, token) used for telemetry uploads. Process-wide because the
/// uploaders run on their own tasks and only have a server URL.
static UPLOAD_CREDS: Mutex<Option<(String, Secret)>> = Mutex::new(None);

pub fn set_credentials(node_id: &str, token: &str) {
    let (node_id, token) = (node_id.trim(), token.trim());
    if node_id.is_empty() || token.is_empty() {
        return;
    }
    *UPLOAD_CREDS.lock().unwrap() = Some((node_id.to_string(), Secret::new(token)));
}

pub fn clear_credentials() {
    *UPLOAD_CREDS.lock().unwrap() = None;
}

pub fn has_token() -> bool {
    UPLOAD_CREDS.lock().unwrap().is_some()
}

/// The current token, for persisting to the config file.
pub fn token() -> Option<Secret> {
    UPLOAD_CREDS.lock().unwrap().as_ref().map(|(_, t)| t.clone())
}

/// Call with the status of an upload response. A 401 means the backend no
/// longer accepts our token (revoked / rotated): drop it so the heartbeat loop
/// asks for a new one instead of resending a dead credential forever.
pub fn note_upload_status(status: reqwest::StatusCode) {
    if status == reqwest::StatusCode::UNAUTHORIZED && has_token() {
        log::warn!("upload rejected with 401; discarding node token");
        clear_credentials();
    }
}

/// Build the per-node upload headers. Pure: no global state.
pub fn upload_headers_for(creds: Option<(&str, &Secret)>) -> HeaderMap {
    let mut map = HeaderMap::new();
    let Some((node_id, token)) = creds else { return map };
    if let (Ok(id), Ok(mut tok)) = (
        HeaderValue::from_str(node_id),
        HeaderValue::from_str(token.expose()),
    ) {
        tok.set_sensitive(true);
        map.insert(HeaderName::from_static("x-aegis-node-id"), id);
        map.insert(HeaderName::from_static("x-aegis-node-token"), tok);
    } else {
        log::warn!("node credentials contain characters that cannot be sent in a header");
    }
    map
}

/// Headers for a telemetry upload from the current node. Empty until the node
/// holds a token. Attach with `request.headers(node_auth::upload_headers())`.
pub fn upload_headers() -> HeaderMap {
    let guard = UPLOAD_CREDS.lock().unwrap();
    upload_headers_for(guard.as_ref().map(|(id, t)| (id.as_str(), t)))
}

/// Build the auth headers for a given secret. Pure: no environment access.
pub fn headers_for(secret: Option<&str>) -> HeaderMap {
    let mut map = HeaderMap::new();
    let secret = match secret.map(str::trim) {
        Some(s) if !s.is_empty() => s,
        _ => return map,
    };
    if let Ok(mut value) = HeaderValue::from_str(secret) {
        // Keeps the value out of Debug output and marks it sensitive for HTTP/2 HPACK.
        value.set_sensitive(true);
        if let Ok(name) = HeaderName::from_bytes(NODE_AUTH_HEADER.as_bytes()) {
            map.insert(name, value);
        }
    } else {
        log::warn!("{} contains characters that cannot be sent in a header", SECRET_ENV);
    }
    map
}

/// Headers for the current process environment. Attach with
/// `request.headers(node_auth::headers())`.
pub fn headers() -> HeaderMap {
    headers_for(std::env::var(SECRET_ENV).ok().as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_secret_sends_no_header() {
        assert!(headers_for(None).is_empty());
        assert!(headers_for(Some("")).is_empty());
        assert!(headers_for(Some("   ")).is_empty());
    }

    #[test]
    fn secret_is_sent_trimmed_and_marked_sensitive() {
        let map = headers_for(Some("  s3cret \n"));
        let v = map.get(NODE_AUTH_HEADER).expect("header present");
        assert_eq!(v.to_str().unwrap(), "s3cret");
        assert!(v.is_sensitive());
        assert!(!format!("{:?}", map).contains("s3cret"));
    }

    #[test]
    fn unsendable_secret_is_dropped() {
        assert!(headers_for(Some("bad\u{7f}value")).is_empty());
    }

    #[test]
    fn upload_headers_carry_node_id_and_sensitive_token() {
        let tok = Secret::new("tok-abc");
        let map = upload_headers_for(Some(("node-1", &tok)));
        assert_eq!(map.get(NODE_ID_HEADER).unwrap(), "node-1");
        let v = map.get(NODE_TOKEN_HEADER).expect("token header");
        assert_eq!(v.to_str().unwrap(), "tok-abc");
        assert!(v.is_sensitive());
        assert!(!format!("{:?}", map).contains("tok-abc"));
        // the shared secret is not part of upload auth
        assert!(map.get(NODE_AUTH_HEADER).is_none());
        assert!(upload_headers_for(None).is_empty());
    }

    #[test]
    fn secret_debug_is_redacted_and_serde_is_a_plain_string() {
        let tok = Secret::new("tok-abc");
        assert!(!format!("{:?}", tok).contains("tok-abc"));
        assert_eq!(serde_json::to_string(&tok).unwrap(), "\"tok-abc\"");
        let back: Secret = serde_json::from_str("\"tok-abc\"").unwrap();
        assert_eq!(back.expose(), "tok-abc");
    }

    // One test owns the process-wide store so parallel tests cannot race on it.
    #[test]
    fn credential_store_lifecycle_and_401_discard() {
        clear_credentials();
        assert!(!has_token() && upload_headers().is_empty());
        set_credentials("", "t"); // ignored
        assert!(!has_token());
        set_credentials("node-1", "tok-abc");
        assert!(has_token());
        assert_eq!(token().unwrap().expose(), "tok-abc");
        assert_eq!(upload_headers().get(NODE_ID_HEADER).unwrap(), "node-1");
        note_upload_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(has_token());
        note_upload_status(reqwest::StatusCode::UNAUTHORIZED);
        assert!(!has_token() && upload_headers().is_empty());
    }

    #[test]
    fn header_is_applied_to_a_request() {
        let req = reqwest::Client::new()
            .post("http://localhost/x")
            .headers(headers_for(Some("k")))
            .build()
            .unwrap();
        assert_eq!(req.headers().get(NODE_AUTH_HEADER).unwrap(), "k");
    }
}
