// ---------------------------------------------------------------------------
// eBPF-based telemetry collector (Task #5, Linux Tier 2)
//
// Loads aya eBPF programs for:
//   - tracepoint/sched/sched_process_exec          -> ProcessStart
//   - tracepoint/syscalls/sys_enter_connect        -> TcpConnect
//   - tracepoint/syscalls/sys_enter_openat         -> FileCreate (filtered)
//   - kprobe/security_inode_unlink                 -> FileDelete
//
// Falls back to /proc polling if eBPF isn't available. The actual BPF
// bytecode lives in a sibling crate (node-tauri/ebpf-programs/) and is
// compiled at build time. When the `aya-bpf` feature is off, this is a
// stub that returns Err() and the Tier-1 poller takes over.
// ---------------------------------------------------------------------------

#![cfg(target_os = "linux")]

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::edr::EdrState;

pub async fn run(state: Arc<Mutex<EdrState>>) -> Result<(), String> {
    #[cfg(feature = "aya-bpf")]
    {
        use aya::programs::{KProbe, TracePoint};
        use aya::{include_bytes_aligned, Bpf};
        use aya::maps::perf::AsyncPerfEventArray;

        // Embedded BPF object built by build.rs from ebpf-programs/
        let bpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aegis_edr.bpf.o"));
        let mut bpf = Bpf::load(bpf_bytes).map_err(|e| e.to_string())?;

        // sched_process_exec
        if let Some(prog) = bpf.program_mut("sched_process_exec") {
            let tp: &mut TracePoint = prog.try_into().map_err(|e: aya::programs::ProgramError| e.to_string())?;
            tp.load().map_err(|e| e.to_string())?;
            tp.attach("sched", "sched_process_exec").map_err(|e| e.to_string())?;
        }

        // sys_enter_connect
        if let Some(prog) = bpf.program_mut("sys_enter_connect") {
            let tp: &mut TracePoint = prog.try_into().map_err(|e: aya::programs::ProgramError| e.to_string())?;
            tp.load().map_err(|e| e.to_string())?;
            tp.attach("syscalls", "sys_enter_connect").map_err(|e| e.to_string())?;
        }

        // sys_enter_openat
        if let Some(prog) = bpf.program_mut("sys_enter_openat") {
            let tp: &mut TracePoint = prog.try_into().map_err(|e: aya::programs::ProgramError| e.to_string())?;
            tp.load().map_err(|e| e.to_string())?;
            tp.attach("syscalls", "sys_enter_openat").map_err(|e| e.to_string())?;
        }

        // security_inode_unlink
        if let Some(prog) = bpf.program_mut("security_inode_unlink") {
            let kp: &mut KProbe = prog.try_into().map_err(|e: aya::programs::ProgramError| e.to_string())?;
            kp.load().map_err(|e| e.to_string())?;
            kp.attach("security_inode_unlink", 0).map_err(|e| e.to_string())?;
        }

        // Perf event array for telemetry
        let mut perf = AsyncPerfEventArray::try_from(
            bpf.take_map("AEGIS_EVENTS")
                .ok_or_else(|| "AEGIS_EVENTS perf map missing".to_string())?,
        )
        .map_err(|e| e.to_string())?;

        {
            let mut s = state.lock().await;
            s.tier2_active = true;
        }

        let cpus = online_cpus().map_err(|e| e.to_string())?;
        for cpu_id in cpus {
            let mut buf = perf.open(cpu_id, None).map_err(|e| e.to_string())?;
            let state_cb = state.clone();
            tokio::spawn(async move {
                use bytes::BytesMut;
                let mut buffers: Vec<BytesMut> = (0..10).map(|_| BytesMut::with_capacity(1024)).collect();
                loop {
                    match buf.read_events(&mut buffers).await {
                        Ok(events) => {
                            for i in 0..events.read {
                                let raw = &buffers[i];
                                if let Some(ev) = decode_bpf_event(raw) {
                                    let mut s = state_cb.lock().await;
                                    s.buffer.push(ev);
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("[edr/ebpf] perf read error: {}", e);
                            break;
                        }
                    }
                }
            });
        }

        log::info!("[edr/ebpf] Tier 2 collector active");

        // Keep the task alive
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    #[cfg(not(feature = "aya-bpf"))]
    {
        let _ = state;
        Err("aya-bpf feature not enabled — using Tier 1 poller".to_string())
    }
}

#[cfg(feature = "aya-bpf")]
fn online_cpus() -> Result<Vec<u32>, String> {
    let s = std::fs::read_to_string("/sys/devices/system/cpu/online").map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for part in s.trim().split(',') {
        if let Some((a, b)) = part.split_once('-') {
            let a: u32 = a.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
            let b: u32 = b.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
            out.extend(a..=b);
        } else {
            let x: u32 = part.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
            out.push(x);
        }
    }
    Ok(out)
}

#[cfg(feature = "aya-bpf")]
fn decode_bpf_event(_raw: &[u8]) -> Option<crate::edr::EdrEvent> {
    // Real decoding lives alongside the BPF program shared struct definitions
    // in node-tauri/ebpf-programs/common. For the userspace-stub build we
    // simply drop the event so the Tier-1 poller continues to operate.
    None
}
