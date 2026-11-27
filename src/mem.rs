//! Read-only live-process scan (`/proc/<pid>/mem`, no ptrace).
//!
//! Opens `maps` + `mem` with read-only access only. No attach, no
//! injection, no threads. Finds Lua text runs and bytecode markers via
//! [`crate::carve`]. Key dumping is deliberately NOT implemented here.

use anyhow::{Context, Result};
use std::fs::File;
use std::os::unix::fs::FileExt;

use crate::carve::{self, Hit};

#[derive(Debug, Clone)]
pub struct Region {
    pub start: u64,
    pub end: u64,
}

/// Parse readable, non-guarded mappings from `/proc/<pid>/maps`.
pub fn readable_regions(pid: u32) -> Result<Vec<Region>> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).context("read maps")?;
    let mut out = Vec::new();
    for line in maps.lines() {
        let mut cols = line.split_whitespace();
        let range = cols.next().unwrap_or("");
        let perms = cols.next().unwrap_or("");
        if !perms.starts_with('r') {
            continue;
        }
        // Skip guard pages / special mappings that pread poorly.
        if line.contains("[vvar]") || line.contains("[vsyscall]") {
            continue;
        }
        let Some((a, b)) = range.split_once('-') else { continue };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) else {
            continue
        };
        if end > start {
            out.push(Region { start, end });
        }
    }
    Ok(out)
}

/// Scan a process address space, calling `on_hit(addr, hit)` per find.
/// Reads in 1 MiB chunks with 4 KiB overlap so runs crossing chunk
/// borders are still caught.
pub fn scan_pid(pid: u32, mut on_hit: impl FnMut(u64, Hit) -> Result<()>) -> Result<()> {
    const CHUNK: u64 = 1024 * 1024;
    const OVERLAP: usize = 4096;
    let mem = File::open(format!("/proc/{pid}/mem")).context("open mem (read-only)")?;
    for r in readable_regions(pid)? {
        let mut off = r.start;
        let mut carry = Vec::new();
        while off < r.end {
            let want = (r.end - off).min(CHUNK) as usize;
            let mut buf = vec![0u8; want];
            let n = mem.read_at(&mut buf, off).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.truncate(n);
            // Prepend tail of previous chunk for border continuity.
            let mut joined = std::mem::take(&mut carry);
            let base = off - joined.len() as u64;
            joined.extend_from_slice(&buf);
            for h in carve::carve(&joined, true) {
                // Skip hits fully inside the previous chunk (already reported).
                if (base + h.offset as u64) < off {
                    continue;
                }
                on_hit(base + h.offset as u64, h)?;
            }
            carry = buf[buf.len().saturating_sub(OVERLAP)..].to_vec();
            off += n as u64;
        }
    }
    Ok(())
}
