// ---------------------------------------------------------------------------
// Node -> backend authentication header (single seam for every HTTP call)
//
// The backend's node-facing routes (/nodes/*) authenticate with the shared
// secret AEGIS_NODE_SECRET, presented as `X-AEGIS-Node-Auth`
// (backend/app/api/nodes.py::_verify_node_secret). The agent reads the same
// value from its own environment at call time; nothing is compiled in, and
// the value is never logged. When it is unset no header is sent, which is
// what a backend running in compat mode (no secret configured) expects.
// ---------------------------------------------------------------------------

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

pub const NODE_AUTH_HEADER: &str = "X-AEGIS-Node-Auth";
const SECRET_ENV: &str = "AEGIS_NODE_SECRET";

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
    fn header_is_applied_to_a_request() {
        let req = reqwest::Client::new()
            .post("http://localhost/x")
            .headers(headers_for(Some("k")))
            .build()
            .unwrap();
        assert_eq!(req.headers().get(NODE_AUTH_HEADER).unwrap(), "k");
    }
}
