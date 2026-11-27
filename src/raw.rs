//! YooAsset raw files: XOR-0x40 blobs (signed Lua bytecode, JSON, ...).
//!
//! `raw_nostreaming_package` / `raw_streaming_package` hold raw files with
//! obfuscated names. Lua arrives as: XOR-0x40, 128-byte RSA signature,
//! then Lua 5.3 bytecode whose chunk name embeds the original
//! `.../Lua/<category>/<path>.lua` (backslashes, `../Lua/` prefixed).

use crate::sig;

/// A decoded raw blob.
#[derive(Debug)]
pub struct RawHit {
    pub kind: RawKind,
    pub body: Vec<u8>,
    pub sig_ok: bool,
    pub sig_key: Option<sig::KeyUsed>,
    /// Original `Lua/...` path from the bytecode chunk name, if found.
    pub chunk_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawKind {
    Bytecode,
    Text,
    Json,
    Other,
}

/// XOR-decode + classify. Returns `None` when the blob is not Lua-ish.
pub fn process(data: &[u8]) -> Option<RawHit> {
    if data.len() < 16 {
        return None;
    }
    let xored: Vec<u8> = data.iter().map(|b| b ^ crate::decrypt::STREAM_XOR_KEY).collect();
    // Bytecode with signature (the common Lua case).
    if xored.len() > sig::SIG_LEN {
        let tail = &xored[sig::SIG_LEN..];
        if tail.starts_with(b"\x1bLua") || tail.starts_with(b"\x1bLJ") {
            let stripped = sig::strip(&xored).ok()?;
            let chunk = extract_chunk_path(&stripped.body);
            return Some(RawHit {
                kind: RawKind::Bytecode,
                body: stripped.body,
                sig_ok: stripped.sig_ok,
                sig_key: stripped.key,
                chunk_path: chunk,
            });
        }
    }
    // Unsigned bytecode (mem carves, future-proofing).
    if xored.starts_with(b"\x1bLua") || xored.starts_with(b"\x1bLJ") {
        let chunk = extract_chunk_path(&xored);
        return Some(RawHit {
            kind: RawKind::Bytecode,
            body: xored,
            sig_ok: false,
            sig_key: None,
            chunk_path: chunk,
        });
    }
    // Text / JSON (configs; signatures apply to Lua only, but try anyway).
    // Gate: must be valid UTF-8 (audio blobs XOR to '@'-runs but are not).
    let stripped = sig::strip(&xored).ok()?;
    let body = stripped.body;
    if std::str::from_utf8(&body).is_err() {
        return None;
    }
    let trimmed = body.iter().position(|&b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\xEF' | b'\xBB' | b'\xBF')).map(|i| &body[i..]).unwrap_or(&body[..]);
    if trimmed.starts_with(b"{") || trimmed.starts_with(b"[") {
        if is_mostly_text(&body) {
            return Some(RawHit {
                kind: RawKind::Json,
                sig_ok: stripped.sig_ok,
                sig_key: stripped.key,
                chunk_path: None,
                body,
            });
        }
        return None;
    }
    if is_mostly_text(&body) && looks_like_lua(&body) {
        let chunk_path = extract_chunk_path(&body);
        return Some(RawHit {
            kind: RawKind::Text,
            body,
            sig_ok: stripped.sig_ok,
            sig_key: stripped.key,
            chunk_path,
        });
    }
    None
}

fn is_mostly_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let text = data
        .iter()
        .filter(|&&b| matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E) || b >= 0x80)
        .count();
    text * 100 / data.len() >= 85
}

fn looks_like_lua(body: &[u8]) -> bool {
    crate::carve::looks_like_lua_pub(body)
}

/// Find `...Lua/...x.lua` inside bytecode/text; normalize to `a/b/c.lua`.
pub fn extract_chunk_path(body: &[u8]) -> Option<String> {
    // Scan for `.lua` endings, walk back over path chars, prefer one with Lua/.
    let mut best: Option<(usize, String)> = None;
    for (i, w) in body.windows(4).enumerate() {
        if w != b".lua" {
            continue;
        }
        let mut s = i;
        while s > 0 {
            let c = body[s - 1];
            if c.is_ascii_alphanumeric() || matches!(c, b'/' | b'\\' | b'.' | b'_' | b'-' | b'+') {
                s -= 1;
            } else {
                break;
            }
        }
        let mut cand = String::from_utf8_lossy(&body[s..i + 4]).into_owned();
        cand = cand.replace('\\', "/");
        let lower = cand.to_lowercase();
        if let Some(pos) = lower.find("lua/") {
            let rel = cand[pos + 4..].to_string();
            // Prefer the longest (full `../Lua/...` form over fragments).
            if best.as_ref().map(|(_, b)| b.len() < rel.len()).unwrap_or(true) {
                best = Some((s, rel));
            }
        }
    }
    best.map(|(_, b)| b)
}

/// Map a chunk path (`src/a/b.lua`, `configShell/chs/c.lua`) to output
/// identity. No arch segment exists in raw chunk names.
pub fn chunk_identity(chunk: &str) -> (String, Option<String>) {
    let rel = chunk.trim_start_matches('/');
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.len() >= 2 {
        let module = rel.trim_end_matches(".lua").replace('/', ".");
        return (rel.to_string(), Some(module));
    }
    (format!("_misc/{rel}"), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_extract() {
        let body = b"xxxxP3.Daily.PC.JP.OB1.0.Release/Client/Assets\\../Lua/src\\ui\\a\\b.lua\0junk.lua";
        let c = extract_chunk_path(body).unwrap();
        assert_eq!(c, "src/ui/a/b.lua");
        let (rel, module) = chunk_identity(&c);
        assert_eq!(rel, "src/ui/a/b.lua");
        assert_eq!(module.as_deref(), Some("src.ui.a.b"));
    }
}
