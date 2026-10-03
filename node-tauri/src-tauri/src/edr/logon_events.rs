// ---------------------------------------------------------------------------
// Failed-logon (Security 4625) parsing and burst tracking.
//
// Reads `wevtutil ... /f:xml`, whose EventData field names are the same on
// every Windows language (the text format is localized, so looking up
// "Source Network Address" silently failed on a Spanish install and every
// failure was filed under the source "unknown").
//
// A burst is 5 failures within 60 s against the SAME subject: the remote
// address when there is one, otherwise the target account. Every record is
// counted once (by EventRecordID): the poller re-reads the newest records on
// each cycle, and counting the same record again made one old burst fire an
// alert every ~30 s for 19 minutes.
//
// Platform neutral on purpose so it is unit-tested everywhere.
// ---------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const BURST_THRESHOLD: usize = 5;
pub const BURST_WINDOW: Duration = Duration::from_secs(60);
/// Records older than this on the very first poll are history, not a live burst.
const FIRST_POLL_MAX_AGE_SECS: i64 = 60;

#[derive(Debug, Clone, PartialEq)]
pub struct FailedLogon {
    pub record_id: u64,
    pub at: Option<DateTime<Utc>>,
    pub target_account: String,
    pub target_domain: String,
    pub logon_type: String,
    /// Remote address, `None` for a local/blank one ("-", "::1", "127.0.0.1").
    pub source_ip: Option<String>,
    pub caller_process: String,
    pub workstation: String,
    pub status: String,
    pub sub_status: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Burst {
    pub subject: String,
    pub count: usize,
    pub last: FailedLogon,
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn data_field(chunk: &str, name: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let needle = format!("Name={q}{name}{q}", q = quote);
        if let Some(pos) = chunk.find(&needle) {
            let rest = &chunk[pos + needle.len()..];
            let open = rest.find('>')?;
            // `<Data Name='X' />` is an empty field.
            if rest[..open].ends_with('/') {
                return Some(String::new());
            }
            let body = &rest[open + 1..];
            let close = body.find("</Data>")?;
            return Some(unescape(body[..close].trim()));
        }
    }
    None
}

fn tag_text(chunk: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let start = chunk.find(&open)? + open.len();
    let end = chunk[start..].find(&format!("</{}>", tag))?;
    Some(chunk[start..start + end].trim().to_string())
}

fn system_time(chunk: &str) -> Option<DateTime<Utc>> {
    let pos = chunk.find("SystemTime=")?;
    let rest = &chunk[pos + "SystemTime=".len()..];
    let quote = rest.chars().next()?;
    let end = rest[1..].find(quote)?;
    DateTime::parse_from_rfc3339(&rest[1..1 + end])
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn remote_address(raw: &str) -> Option<String> {
    let v = raw.trim();
    match v {
        "" | "-" | "::1" | "::" | "127.0.0.1" | "localhost" | "0.0.0.0" => None,
        _ => Some(v.to_string()),
    }
}

/// Parse the output of `wevtutil qe Security /q:*[System[(EventID=4625)]] /f:xml`.
pub fn parse_failed_logons(xml: &str) -> Vec<FailedLogon> {
    let mut out = Vec::new();
    for chunk in xml.split("<Event ").skip(1) {
        let Some(record_id) = tag_text(chunk, "EventRecordID").and_then(|v| v.parse::<u64>().ok())
        else {
            continue;
        };
        if tag_text(chunk, "EventID").as_deref() != Some("4625") {
            continue;
        }
        let field = |n: &str| data_field(chunk, n).unwrap_or_default();
        out.push(FailedLogon {
            record_id,
            at: system_time(chunk),
            target_account: field("TargetUserName"),
            target_domain: field("TargetDomainName"),
            logon_type: field("LogonType"),
            source_ip: remote_address(&field("IpAddress")),
            caller_process: field("ProcessName"),
            workstation: field("WorkstationName"),
            status: field("Status"),
            sub_status: field("SubStatus"),
        });
    }
    out
}

#[derive(Default)]
pub struct BurstTracker {
    last_record_id: Option<u64>,
    hits: HashMap<String, Vec<Instant>>,
}

impl BurstTracker {
    pub fn new() -> Self {
        Self::default()
    }

    fn subject(l: &FailedLogon) -> String {
        match &l.source_ip {
            Some(ip) => format!("remote:{}", ip),
            None => format!("account:{}", l.target_account.to_lowercase()),
        }
    }

    /// Feed one poll's records (any order, overlapping previous polls).
    /// Returns a burst per subject that reached the threshold in this call.
    pub fn ingest(&mut self, mut logons: Vec<FailedLogon>, now_utc: DateTime<Utc>, now: Instant) -> Vec<Burst> {
        logons.sort_by_key(|l| l.record_id);
        let first_poll = self.last_record_id.is_none();
        let seen = self.last_record_id.unwrap_or(0);
        let newest = logons.iter().map(|l| l.record_id).max().unwrap_or(seen);
        let mut bursts = Vec::new();

        for l in logons {
            if l.record_id <= seen {
                continue;
            }
            if first_poll {
                // Whatever was already in the log when we started is history.
                let fresh = l
                    .at
                    .map(|t| (now_utc - t).num_seconds() <= FIRST_POLL_MAX_AGE_SECS)
                    .unwrap_or(false);
                if !fresh {
                    continue;
                }
            }
            let subject = Self::subject(&l);
            let hits = self.hits.entry(subject.clone()).or_default();
            hits.retain(|t| now.duration_since(*t) < BURST_WINDOW);
            hits.push(now);
            if hits.len() >= BURST_THRESHOLD {
                let count = hits.len();
                hits.clear();
                bursts.push(Burst { subject, count, last: l });
            }
        }
        self.last_record_id = Some(newest.max(seen));
        self.hits.retain(|_, v| !v.is_empty());
        bursts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: u64, user: &str, ip: &str, secs_ago: i64) -> String {
        let at = (Utc::now() - chrono::Duration::seconds(secs_ago)).to_rfc3339();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <EventID>4625</EventID><TimeCreated SystemTime='{at}'/>\
             <EventRecordID>{id}</EventRecordID></System><EventData>\
             <Data Name='TargetUserName'>{user}</Data><Data Name='TargetDomainName'>WIN-TEST</Data>\
             <Data Name='LogonType'>3</Data><Data Name='IpAddress'>{ip}</Data>\
             <Data Name='ProcessName'>C:\\Windows\\System32\\svchost.exe</Data>\
             <Data Name='WorkstationName'/><Data Name='Status'>0xc000006d</Data>\
             <Data Name='SubStatus'>0xc000006a</Data></EventData></Event>"
        )
    }

    fn parsed(ids: std::ops::RangeInclusive<u64>, user: &str, ip: &str) -> Vec<FailedLogon> {
        let xml: String = ids.map(|i| record(i, user, ip, 5)).collect();
        parse_failed_logons(&xml)
    }

    #[test]
    fn parses_account_type_caller_and_remote_source() {
        let l = &parsed(7..=7, "svc-backup", "192.0.2.10")[0];
        assert_eq!(l.record_id, 7);
        assert_eq!(l.target_account, "svc-backup");
        assert_eq!(l.logon_type, "3");
        assert_eq!(l.source_ip.as_deref(), Some("192.0.2.10"));
        assert_eq!(l.caller_process, "C:\\Windows\\System32\\svchost.exe");
        assert_eq!(l.workstation, "");
        assert_eq!(l.sub_status, "0xc000006a");
        assert!(l.at.is_some());
    }

    #[test]
    fn local_and_blank_addresses_are_not_remote() {
        for ip in ["-", "::1", "127.0.0.1", ""] {
            assert_eq!(parsed(1..=1, "u", ip)[0].source_ip, None, "{ip:?}");
        }
    }

    #[test]
    fn five_failures_for_one_subject_make_one_burst() {
        let mut t = BurstTracker::new();
        let b = t.ingest(parsed(1..=5, "admin", "192.0.2.10"), Utc::now(), Instant::now());
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].subject, "remote:192.0.2.10");
        assert_eq!(b[0].count, 5);
    }

    #[test]
    fn failures_spread_over_different_subjects_never_burst() {
        let mut t = BurstTracker::new();
        let mut v = Vec::new();
        for (i, ip) in ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"].iter().enumerate() {
            v.extend(parsed((i as u64 + 1)..=(i as u64 + 1), "admin", ip));
        }
        assert!(t.ingest(v, Utc::now(), Instant::now()).is_empty());
    }

    #[test]
    fn local_failures_group_by_account_not_all_together() {
        let mut t = BurstTracker::new();
        let mut v = parsed(1..=3, "alice", "-");
        v.extend(parsed(4..=6, "bob", "-"));
        assert!(t.ingest(v, Utc::now(), Instant::now()).is_empty());
        let b = t.ingest(parsed(7..=8, "alice", "-"), Utc::now(), Instant::now());
        assert_eq!(b[0].subject, "account:alice");
    }

    #[test]
    fn rereading_the_same_records_does_not_count_again() {
        let mut t = BurstTracker::new();
        let now = Instant::now();
        let recs = parsed(1..=4, "admin", "192.0.2.10");
        assert!(t.ingest(recs.clone(), Utc::now(), now).is_empty());
        for i in 0..20 {
            // Every later poll returns the same newest records.
            let again = t.ingest(recs.clone(), Utc::now(), now + Duration::from_secs(15 * (i + 1)));
            assert!(again.is_empty(), "poll {i} re-counted old records");
        }
    }

    #[test]
    fn history_present_at_startup_is_not_a_burst() {
        let mut t = BurstTracker::new();
        let xml: String = (1..=10).map(|i| record(i, "admin", "192.0.2.10", 3600)).collect();
        assert!(t.ingest(parse_failed_logons(&xml), Utc::now(), Instant::now()).is_empty());
        // ...but a live burst afterwards is still caught.
        let b = t.ingest(parsed(11..=15, "admin", "192.0.2.10"), Utc::now(), Instant::now());
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn failures_older_than_the_window_expire() {
        let mut t = BurstTracker::new();
        let now = Instant::now();
        t.ingest(parsed(1..=4, "admin", "192.0.2.10"), Utc::now(), now);
        let b = t.ingest(parsed(5..=5, "admin", "192.0.2.10"), Utc::now(), now + Duration::from_secs(61));
        assert!(b.is_empty());
    }
}
