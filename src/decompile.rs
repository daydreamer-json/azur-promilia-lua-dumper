//! Lua bytecode detection + built-in decompilation (unluac-rs).

use anyhow::{Context, Result};

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

/// Decompile Lua bytecode with the bundled unluac-rs engine.
/// Returns decompiled source text on success.
pub fn try_decompile(bytecode: &[u8], flavor: Bytecode) -> Result<String> {
    use unluac::decompile::{DecompileDialect, DecompileOptions, decompile};
    use unluac::generate::GenerateMode;
    let mut options = DecompileOptions::default();
    options.dialect = match flavor {
        Bytecode::Lua51 => DecompileDialect::Lua51,
        Bytecode::Lua53 => DecompileDialect::Lua53,
        Bytecode::Lua54 => DecompileDialect::Lua54,
        Bytecode::LuaJit => DecompileDialect::Luajit,
        Bytecode::Unknown => DecompileDialect::Auto,
    };
    // shortcut: permissive keeps bulk runs going on odd chunks.
    options.generate.mode = GenerateMode::Permissive;
    let result = decompile(bytecode, options).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    result
        .state
        .generated
        .map(|g| g.source)
        .context("decompiler produced no output")
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

    #[test]
    fn decompile_rejects_garbage() {
        // Must fail gracefully (no panic) on non-bytecode.
        assert!(try_decompile(b"return 1", Bytecode::Unknown).is_err());
        assert!(try_decompile(&[0u8; 64], Bytecode::Unknown).is_err());
    }
}
