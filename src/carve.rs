//! Keyless fallback: carve Lua sources / bytecode out of raw bytes.
//!
//! Used when a bundle cannot be fully parsed (missing `--decrypt-key`)
//! and for read-only `/proc` memory scans. A text run preceded by a
//! verifiable 128-byte RSA signature is a strong hit; other Lua-looking
//! runs are weak hits. `\x1bLua` / `\x1bLJ` markers catch bytecode.

use crate::decompile::classify_bytecode;
use crate::sig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarveKind {
    /// 128-byte signature verified.
    SignedText,
    /// Looks like Lua but no verifiable signature.
    PlainText,
    /// Lua bytecode (`\x1bLua` / LuaJIT).
    Bytecode,
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub offset: usize,
    pub kind: CarveKind,
    pub data: Vec<u8>,
    pub sig_ok: bool,
}

/// Minimum printable-run length to consider (shorter runs are noise).
const MIN_RUN: usize = 32;

fn is_text_byte(b: u8) -> bool {
    matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E) || b >= 0x80
}

const LUA_HINTS: &[&[u8]] = &[
    b"function",
    b"local ",
    b"require",
    b"return ",
    b"end\n",
    b"end\r",
    b"if ",
    b"for ",
    b"while ",
    b"then\n",
    b"do\n",
    b"--",
    b"nil",
    b"true",
    b"false",
];

/// Public wrapper for reuse by the raw-file classifier.
pub fn looks_like_lua_pub(run: &[u8]) -> bool {
    looks_like_lua(run)
}

fn looks_like_lua(run: &[u8]) -> bool {
    let mut hits = 0;
    for h in LUA_HINTS {
        if run.windows(h.len()).any(|w| w == *h) {
            hits += 1;
            // shortcut: 3 distinct anchors; binary noise rarely has 2, never 3.
            if hits >= 3 {
                return true;
            }
        }
    }
    false
}

/// Carve `data`. `want_bytecode` also scans for `\x1bLua` / `\x1bLJ`.
pub fn carve(data: &[u8], want_bytecode: bool) -> Vec<Hit> {
    let mut hits = Vec::new();
    // 1. Text runs.
    let mut i = 0;
    while i < data.len() {
        if !is_text_byte(data[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && is_text_byte(data[i]) {
            i += 1;
        }
        let run = &data[start..i];
        if run.len() < MIN_RUN {
            continue;
        }
        // Trim trailing whitespace-ish padding.
        let mut end = run.len();
        while end > 0 && matches!(run[end - 1], b'\0' | b' ' | b'\n' | b'\r' | b'\t') {
            end -= 1;
        }
        let run = &run[..end];
        if run.len() < MIN_RUN || !looks_like_lua(run) {
            continue;
        }
        // Strong hit? 128 bytes before the run verify as signature.
        let mut kind = CarveKind::PlainText;
        let mut sig_ok = false;
        let mut body = run.to_vec();
        if start >= sig::SIG_LEN {
            let total = (run.len() + sig::SIG_LEN).min(data.len() - (start - sig::SIG_LEN));
            if let Ok(Some((verified, _))) =
                sig::verify(&data[start - sig::SIG_LEN..start - sig::SIG_LEN + total])
            {
                kind = CarveKind::SignedText;
                sig_ok = true;
                body = verified;
            }
        }
        hits.push(Hit { offset: start, kind, data: body, sig_ok });
    }
    // 2. Bytecode markers (strict header gate).
    if want_bytecode {
        for marker in [b"\x1bLua".as_slice(), b"\x1bLJ".as_slice()] {
            let mut from = 0;
            while let Some(pos) = memchr::memmem::find(&data[from..], marker) {
                let abs_pos = from + pos;
                if !crate::decompile::valid_bytecode_header(&data[abs_pos..]) {
                    from = abs_pos + 1;
                    continue;
                }
                let end = carve_bytecode_end(data, abs_pos);
                let blob = data[abs_pos..end].to_vec();
                let _ = classify_bytecode(&blob);
                hits.push(Hit {
                    offset: abs_pos,
                    kind: CarveKind::Bytecode,
                    data: blob,
                    sig_ok: false,
                });
                from = end.max(abs_pos + 1);
                if from >= data.len() {
                    break;
                }
            }
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits
}

/// Extend bytecode until a long zero/whitespace gap, EOF, or the cap.
fn carve_bytecode_end(data: &[u8], start: usize) -> usize {
    const CAP: usize = 8 * 1024 * 1024;
    let limit = (start + CAP).min(data.len());
    let mut gap = 0;
    let mut i = start;
    while i < limit {
        if data[i] == 0 {
            gap += 1;
            if gap >= 64 {
                return i + 1 - 64;
            }
        } else {
            gap = 0;
        }
        i += 1;
    }
    limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_lua_text() {
        let mut blob = vec![0u8; 32];
        blob.extend_from_slice(b"local function foo() return require(\"a.b\") end\n");
        blob.extend_from_slice(&[0u8; 128]);
        let hits = carve(&blob, false);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, CarveKind::PlainText);
    }

    #[test]
    fn finds_bytecode_marker() {
        let mut blob = b"junkjunk".to_vec();
        blob.extend_from_slice(b"\x1bLua\x53\x00\x19\x93\x0d\x0a\x1a\x0apayload-bytes-here");
        blob.extend_from_slice(&[0u8; 128]);
        let hits = carve(&blob, true);
        assert!(hits.iter().any(|h| h.kind == CarveKind::Bytecode));
    }

    #[test]
    fn rejects_luajit_noise() {
        // Random `\x1bLJ` in encrypted data must not carve.
        let mut blob = vec![0xAAu8; 64];
        blob.extend_from_slice(b"\x1bLJ\x4e More random bytes here ....");
        blob.extend_from_slice(&[0u8; 128]);
        let hits = carve(&blob, true);
        assert!(!hits.iter().any(|h| h.kind == CarveKind::Bytecode));
    }
}
