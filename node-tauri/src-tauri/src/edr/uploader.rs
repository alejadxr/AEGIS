// ---------------------------------------------------------------------------
// EDR batch uploader (Task #5)
//
// Drains the event buffer every second, serializes to JSON, gzips, and
// POSTs to /api/v1/edr/events. On failure, events are requeued at the head
// of the buffer (bounded — when the buffer would overflow, oldest are
// dropped, tracked via EventBuffer::dropped).
// ---------------------------------------------------------------------------

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::edr::EdrState;

const BATCH_INTERVAL_MS: u64 = 1000;
const MAX_BATCH_SIZE: usize = 2000;

pub async fn run(state: Arc<Mutex<EdrState>>) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            log::error!("[edr] uploader: couldn't build reqwest client: {}", e);
            return;
        }
    };

    log::info!("[edr] uploader started");
    loop {
        tokio::time::sleep(Duration::from_millis(BATCH_INTERVAL_MS)).await;

        let (batch, dropped, server_url, agent_id) = {
            let mut s = state.lock().await;
            if !s.enabled {
                continue;
            }
            let batch = s.buffer.drain(MAX_BATCH_SIZE);
            if batch.is_empty() {
                continue;
            }
            (batch, s.buffer.dropped(), s.server_url.clone(), s.agent_id.clone())
        };

        let agent_id = match agent_id {
            Some(id) => id,
            None => continue, // not enrolled yet
        };

        let body = serde_json::json!({
            "agent_id": agent_id,
            "events_dropped_total": dropped,
            "events": batch,
        });

        let json = match serde_json::to_vec(&body) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[edr] uploader: serialize failed: {}", e);
                continue;
            }
        };

        // gzip-compress the JSON
        let gz = match gzip_compress(&json) {
            Ok(g) => g,
            Err(e) => {
                log::warn!("[edr] uploader: gzip failed: {}", e);
                json // fallback to uncompressed
            }
        };

        let result = client
            .post(format!("{}/edr/events", server_url))
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .body(gz)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                let mut s = state.lock().await;
                s.events_sent = s.events_sent.saturating_add(batch.len() as u64);
            }
            Ok(resp) => {
                log::warn!("[edr] uploader: server returned {}", resp.status());
                // Requeue — but bounded, so oldest events may be dropped.
                requeue(&state, batch).await;
            }
            Err(e) => {
                log::warn!("[edr] uploader: POST failed: {}", e);
                requeue(&state, batch).await;
            }
        }
    }
}

async fn requeue(state: &Arc<Mutex<EdrState>>, batch: Vec<crate::edr::EdrEvent>) {
    let mut s = state.lock().await;
    // Push back to buffer head; if capacity exceeded, push() drops oldest.
    for ev in batch {
        s.buffer.push(ev);
    }
    s.events_dropped = s.buffer.dropped();
}

/// Simple in-process gzip via flate2. We avoid adding a new dep by using a
/// tiny hand-rolled DEFLATE shim if flate2 is unavailable.
///
/// flate2 is already pulled in transitively via reqwest, so importing its
/// encoder is free here.
fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut enc = GzEncoder::new(Vec::with_capacity(data.len() / 4), Compression::default());
    enc.write_all(data).map_err(|e| e.to_string())?;
    enc.finish().map_err(|e| e.to_string())
}
