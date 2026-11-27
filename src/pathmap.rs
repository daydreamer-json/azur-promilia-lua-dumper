//! Module-structure restoration.
//!
//! `LuaManager.ReadBytesFiles` looks up
//! `Lua/<arch: 32|64>/<category>/<dotted.name as path>.bytes`.
//! Node paths in that shape map back to `out/<arch>/<category>/...lua`
//! plus the dotted module name (`require` form).

/// A restored Lua asset identity.
#[derive(Debug, Clone)]
pub struct Identity {
    /// e.g. `64/src/foo/bar.lua`
    pub rel_path: String,
    /// e.g. `foo.bar` (None when the shape is unknown)
    pub module: Option<String>,
    pub arch: Option<String>,
    pub category: Option<String>,
}

const CATEGORIES: &[&str] = &["src", "config", "configShell", "lang"];

/// Keep output paths filesystem-safe.
pub fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '_' | '-' | '+') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Restore identity from a bundle node path or loose-file path.
pub fn restore(node_path: &str) -> Identity {
    // Find a `Lua/` (or `lua/`) segment; match the ReadBytesFiles layout.
    let lower = node_path.to_lowercase();
    if let Some(idx) = lower.find("lua/") {
        let rel = &node_path[idx + 4..];
        let rel = rel.strip_suffix(".bytes").unwrap_or(rel);
        let rel = rel.strip_suffix(".lua").unwrap_or(rel);
        let parts: Vec<&str> = rel.split('/').collect();
        if parts.len() >= 3 && (parts[0] == "32" || parts[0] == "64") && CATEGORIES.contains(&parts[1]) {
            let rest = parts[2..].join("/");
            let module = parts[2..].join(".");
            return Identity {
                rel_path: format!("{}/{}/{}.lua", parts[0], parts[1], sanitize(&rest)),
                module: Some(sanitize(&module)),
                arch: Some(parts[0].to_string()),
                category: Some(parts[1].to_string()),
            };
        }
        // Lua/ prefix but unknown shape: preserve hierarchy anyway.
        let s = sanitize(rel);
        return Identity {
            rel_path: format!("_lua/{s}.lua"),
            module: None,
            arch: None,
            category: None,
        };
    }
    // Non-Lua asset (e.g. ast_conf summary): keep the file name.
    let base = node_path.rsplit('/').next().unwrap_or(node_path);
    let base = base.rsplit('\\').next().unwrap_or(base);
    Identity {
        rel_path: format!("_misc/{}.bin", sanitize(base)),
        module: None,
        arch: None,
        category: None,
    }
}

/// Collect `require "a.b.c"` targets from Lua source (best-effort).
pub fn extract_requires(src: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(src);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(i) = rest.find("require") {
        rest = &rest[i + 7..];
        let r = rest.trim_start();
        let r = r.strip_prefix('(').map(|s| s.trim_start()).unwrap_or(r);
        let quote = r.chars().next();
        if !matches!(quote, Some('"') | Some('\'')) {
            continue;
        }
        let q = quote.unwrap();
        let inner = &r[1..];
        if let Some(end) = inner.find(q) {
            let name = &inner[..end];
            if !name.is_empty()
                && name.len() < 256
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
            {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lua_layout() {
        let id = restore("Assets/Addressables/Lua/64/src/battle/skill.lua");
        assert_eq!(id.rel_path, "64/src/battle/skill.lua");
        assert_eq!(id.module.as_deref(), Some("battle.skill"));
        let id = restore("Lua/32/config/abc.bytes");
        assert_eq!(id.rel_path, "32/config/abc.lua");
        assert_eq!(id.module.as_deref(), Some("abc"));
    }

    #[test]
    fn misc_fallback() {
        let id = restore("CAB-deadbeef");
        assert!(id.rel_path.starts_with("_misc/"));
        assert!(id.module.is_none());
    }

    #[test]
    fn requires() {
        let r = extract_requires(b"local a=require(\"foo.bar\") require('x') --require(\"nope)");
        assert!(r.contains(&"foo.bar".to_string()));
        assert!(r.contains(&"x".to_string()));
    }
}
