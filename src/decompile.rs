//! Lua bytecode detection + optional external decompilation.
//!
//! Rust does not reimplement a Lua decompiler here; this module detects
//! the bytecode version from the header and shells out to a user-supplied
//! tool (`unluac`, `luadec`, ...) when `--decompile` is passed.

use anyhow::Result;
use std::process::Command;

/// Bytecode flavor detected from the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bytecode {
    Lua51,
    Lua53,
    Lua54,
    LuaJit,
    Unknown,
}

impl Bytecode {
    pub fn as_str(self) -> &'static str {
        match self {
            Bytecode::Lua51 => "5.1",
            Bytecode::Lua53 => "5.3",
            Bytecode::Lua54 => "5.4",
            Bytecode::LuaJit => "luajit",
            Bytecode::Unknown => "unknown",
        }
    }
}

/// Strict header gate for carving (kills random `\x1bLJ` hits in
/// encrypted blobs). Standard Lua 5.x header required.
pub fn valid_bytecode_header(data: &[u8]) -> bool {
    if data.len() >= 12 && &data[..4] == b"\x1bLua" {
        return matches!(data[4], 0x51 | 0x53 | 0x54)
            && data[5] == 0x00
            && &data[6..12] == b"\x19\x93\r\n\x1a\n";
    }
    if data.len() >= 4 && &data[..3] == b"\x1bLJ" {
        return matches!(data[3], 0x01 | 0x02);
    }
    false
}

/// Classify `\x1bLua<ver>` / `\x1bLJ` blobs.
pub fn classify_bytecode(data: &[u8]) -> Bytecode {
    if data.len() < 5 {
        return Bytecode::Unknown;
    }
    if data.len() >= 3 && &data[..3] == b"\x1bLJ" {
        return Bytecode::LuaJit;
    }
    if data.len() < 5 || &data[..4] != b"\x1bLua" {
        return Bytecode::Unknown;
    }
    match data[4] {
        0x51 => Bytecode::Lua51,
        0x53 => Bytecode::Lua53,
        0x54 => Bytecode::Lua54,
        _ => Bytecode::Unknown,
    }
}

/// Try external decompilers in order; returns decompiled text on success.
pub fn try_decompile(bytecode: &[u8], flavor: Bytecode) -> Result<String> {
    // shortcut: no bundled decompiler; delegate to tools the user installed.
    // unluac handles 5.1-5.4 (these chunks are standard 5.3, no typemap needed).
    let dir = std::env::temp_dir();
    let tmp = dir.join(format!("azur-promilia-lua-dumper-{}.lub", std::process::id()));
    std::fs::write(&tmp, bytecode)?;
    let tmp_s = tmp.to_string_lossy().into_owned();
    let mut argv: Vec<Vec<String>> = Vec::new();
    if let Ok(jar) = std::env::var("UNLUAC_JAR") {
        argv.push(vec!["java".into(), "-jar".into(), jar, tmp_s.clone()]);
    }
    for tool in ["unluac", "luadec"] {
        argv.push(vec![tool.into(), tmp_s.clone()]);
    }
    let _ = flavor;
    for args in &argv {
        if let Ok(out) = Command::new(&args[0]).args(&args[1..]).output() {
            if out.status.success() && !out.stdout.is_empty() {
                let _ = std::fs::remove_file(&tmp);
                return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
            }
        }
    }
    let _ = std::fs::remove_file(&tmp);
    anyhow::bail!("no working decompiler found (set UNLUAC_JAR or install unluac); kept .lub")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(classify_bytecode(b"\x1bLua\x51...."), Bytecode::Lua51);
        assert_eq!(classify_bytecode(b"\x1bLua\x53...."), Bytecode::Lua53);
        assert_eq!(classify_bytecode(b"\x1bLua\x54...."), Bytecode::Lua54);
        assert_eq!(classify_bytecode(b"\x1bLJ....."), Bytecode::LuaJit);
        assert_eq!(classify_bytecode(b"return 1"), Bytecode::Unknown);
    }
}
