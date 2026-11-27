//! `azur-promilia-lua-dumper`: Azur Promilia Lua dumper (static + read-only mem).

use anyhow::{Context, Result};
use azur_promilia_lua_dumper::{carve, decompile, decrypt, mem, pathmap, raw, sig, unitycn, unityfs};
use clap::{Parser, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

/// Built-in UnityCN bundle password (16 chars). Filled by `recover-key`.
const DEFAULT_DECRYPT_KEY: Option<&str> = None;

#[derive(Parser)]
#[command(name = "azur-promilia-lua-dumper", version, about = "Azur Promilia Lua dumper")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Dump Lua from local StreamingAssets (.res tree or single bundle).
    Static {
        /// `.res` root, a package dir, or a single bundle file.
        #[arg(long)]
        res: PathBuf,
        /// Output directory.
        #[arg(long)]
        out: PathBuf,
        /// UnityCN bundle password (16 chars). Falls back to built-in.
        #[arg(long)]
        decrypt_key: Option<String>,
        /// Also run external decompilers on bytecode.
        #[arg(long, default_value_t = false)]
        decompile: bool,
    },
    /// Read-only scan of a live process for Lua text/bytecode.
    Mem {
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        decompile: bool,
    },
    /// Recover the 16-char UnityCN password from header vectors +
    /// static scans (DLL/dat files). No memory access involved.
    RecoverKey {
        /// A UnityFS bundle from the game (for header vectors).
        #[arg(long)]
        bundle: PathBuf,
        /// Files to scan (e.g. GameAssembly.dll).
        #[arg(long, required = true)]
        scan: Vec<PathBuf>,
        /// Exhaustive every-offset scan (slow, finds keys with symbols).
        #[arg(long, default_value_t = false)]
        exhaustive: bool,
    },
}

#[derive(Debug, Serialize, Clone)]
struct FileEntry {
    out: String,
    source: String,
    bundle: String,
    node: String,
    offset: u64,
    size: usize,
    sha256: String,
    sig_ok: bool,
    sig_key: Option<String>,
    kind: String,
    lua_version: Option<String>,
    module: Option<String>,
    requires: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Manifest {
    tool: String,
    version: String,
    kind: String,
    files: Vec<FileEntry>,
    notes: Vec<String>,
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn short_hash(s: &str) -> String {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:08x}", h.finish() & 0xFFFF_FFFF)
}

/// Write `data` under `out/<rel>`, deduping by content on collision.
fn write_unique(out_root: &Path, rel: &str, data: &[u8]) -> Result<PathBuf> {
    let mut dest = out_root.join(rel);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if dest.exists() {
        let prev = std::fs::read(&dest)?;
        if prev == data {
            return Ok(dest);
        }
        let stem = dest
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into());
        let ext = dest
            .extension()
            .map(|s| format!(".{}", s.to_string_lossy()))
            .unwrap_or_default();
        let tag = short_hash(&hex::encode(Sha256::digest(data))[..16]);
        dest = dest.with_file_name(format!("{stem}~{tag}{ext}"));
        if dest.exists() {
            return Ok(dest);
        }
    }
    std::fs::write(&dest, data)?;
    Ok(dest)
}

fn parse_key(s: &str) -> Result<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 16 {
        anyhow::bail!("decrypt key must be exactly 16 chars (got {})", b.len());
    }
    let mut k = [0u8; 16];
    k.copy_from_slice(b);
    Ok(k)
}

fn emit_bytecode(
    out_root: &Path,
    rel_base: &str,
    blob: &[u8],
    entry: &mut FileEntry,
    decompile: bool,
) -> Result<()> {
    let flavor = decompile::classify_bytecode(blob);
    entry.lua_version = Some(flavor.as_str().to_string());
    let dest = write_unique(out_root, &format!("{rel_base}.lub"), blob)?;
    entry.out = dest.to_string_lossy().into_owned();
    if decompile {
        match decompile::try_decompile(blob, flavor) {
            Ok(src) => {
                write_unique(out_root, &format!("{rel_base}.lua"), src.as_bytes())?;
            }
            Err(_) => {}
        }
    }
    Ok(())
}

fn classify_and_write(
    out_root: &Path,
    rel_base: &str,
    raw: &[u8],
    entry: &mut FileEntry,
    decompile: bool,
) -> Result<()> {
    let stripped = sig::strip(raw)?;
    entry.sig_ok = stripped.sig_ok;
    entry.sig_key = stripped.key.map(|k| k.as_str().to_string());
    let body = stripped.body;
    if body.starts_with(b"\x1bLua") || body.starts_with(b"\x1bLJ") {
        entry.kind = "bytecode".to_string();
        emit_bytecode(out_root, rel_base, &body, entry, decompile)?;
    } else {
        entry.kind = "text".to_string();
        entry.requires = pathmap::extract_requires(&body);
        let dest = write_unique(out_root, &format!("{rel_base}.lua"), &body)?;
        entry.out = dest.to_string_lossy().into_owned();
    }
    entry.size = body.len();
    entry.sha256 = sha256_hex(&body);
    Ok(())
}

fn do_static(res: &Path, out: &Path, key: Option<[u8; 16]>, decompile: bool) -> Result<Manifest> {
    let mut files: Vec<FileEntry> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    // Collect inputs: single file, or recursive *.r + loose *.bytes.
    let mut inputs: Vec<PathBuf> = Vec::new();
    if res.is_file() {
        inputs.push(res.to_path_buf());
    } else {
        for e in walkdir::WalkDir::new(res).follow_links(false) {
            let e = e?;
            if !e.file_type().is_file() {
                continue;
            }
            let p = e.path();
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext == "r" || ext == "bytes" || ext == "lub" {
                inputs.push(p.to_path_buf());
            }
        }
    }
    inputs.sort();
    notes.push(format!("inputs: {}", inputs.len()));

    for input in inputs {
        let bundle_name = input
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let data = std::fs::read(&input)
            .with_context(|| format!("read {}", input.display()))?;
        // YooAsset system files: never Lua (also keeps binary manifests
        // out of the text classifier).
        if bundle_name.starts_with("0release_") || bundle_name == "BuildinCatalog.bytes" {
            notes.push(format!("{bundle_name}: yooasset system file, skipped"));
            continue;
        }
        // Loose .bytes: passthrough with path restore.
        if input.extension().and_then(|s| s.to_str()) == Some("bytes") && !decrypt::is_akpk(&data) {
            let id = pathmap::restore(&input.to_string_lossy());
            let mut entry = FileEntry {
                out: String::new(),
                source: "loose".to_string(),
                bundle: bundle_name.clone(),
                node: input.to_string_lossy().into_owned(),
                offset: 0,
                size: data.len(),
                sha256: sha256_hex(&data),
                sig_ok: false,
                sig_key: None,
                kind: "raw".to_string(),
                lua_version: None,
                module: id.module.clone(),
                requires: Vec::new(),
            };
            let rel = id.rel_path.trim_end_matches(".lua").trim_end_matches(".bin");
            // Loose blobs keep their own extension handling via classify.
            let rel = rel.to_string();
            match classify_and_write(out, &rel, &data, &mut entry, decompile) {
                Ok(()) => files.push(entry),
                Err(e) => notes.push(format!("{bundle_name}: loose classify failed: {e}")),
            }
            continue;
        }
        if decrypt::is_akpk(&data) {
            notes.push(format!(
                "{bundle_name}: shortcut: AKPK raw container, parser not yet implemented"
            ));
            continue;
        }
        let (norm, variant) = match decrypt::normalize(&data) {
            Ok(v) => v,
            Err(_) => {
                // Not UnityFS: try YooAsset raw blob (XOR-0x40).
                match raw::process(&data) {
                    Some(hit) => {
                        push_raw_hit(out, &mut files, &mut notes, &input, &bundle_name, hit, decompile)?;
                    }
                    None => notes.push(format!("{bundle_name}: not UnityFS/raw, skipped")),
                }
                continue;
            }
        };
        let _ = variant;
        match unityfs::Bundle::parse(&norm, key.as_ref()) {
            Ok(bundle) => {
                for node in &bundle.nodes {
                    let bytes = match bundle.node_bytes(&bundle.payload, node) {
                        Ok(b) => b,
                        Err(e) => {
                            notes.push(format!("{bundle_name}:{}: {e}", node.path));
                            continue;
                        }
                    };
                    // Only Lua-ish nodes: .bytes/.lua paths or Lua-looking content.
                    let lp = node.path.to_lowercase();
                    let interesting = lp.ends_with(".bytes")
                        || lp.ends_with(".lua")
                        || lp.contains("lua/")
                        || bytes.starts_with(b"\x1bLua")
                        || bytes.starts_with(b"\x1bLJ");
                    if !interesting {
                        continue;
                    }
                    let id = pathmap::restore(&node.path);
                    let mut entry = FileEntry {
                        out: String::new(),
                        source: "bundle-node".to_string(),
                        bundle: bundle_name.clone(),
                        node: node.path.clone(),
                        offset: node.offset,
                        size: bytes.len(),
                        sha256: sha256_hex(bytes),
                        sig_ok: false,
                        sig_key: None,
                        kind: "raw".to_string(),
                        lua_version: None,
                        module: id.module.clone(),
                        requires: Vec::new(),
                    };
                    let rel = id.rel_path;
                    let rel = rel.strip_suffix(".lua").unwrap_or(&rel).to_string();
                    // ast_conf summary blobs land in _misc via restore(); keep as .bin.
                    if rel.starts_with("_misc/") {
                        let dest = write_unique(out, &rel, bytes)?;
                        entry.out = dest.to_string_lossy().into_owned();
                        entry.kind = "misc-blob".to_string();
                        files.push(entry);
                        continue;
                    }
                    match classify_and_write(out, &rel, bytes, &mut entry, decompile) {
                        Ok(()) => files.push(entry),
                        Err(e) => notes.push(format!("{bundle_name}:{}: {e}", node.path)),
                    }
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("decrypt") {
                    // Keyless fallback: carve raw bytes.
                    notes.push(format!("{bundle_name}: encrypted, carve fallback ({msg})"));
                    for h in carve::carve(&norm, true) {
                        let ext = match h.kind {
                            carve::CarveKind::Bytecode => "lub",
                            _ => "lua",
                        };
                        let rel = format!("_carve/{bundle_name}/{:08x}.{ext}", h.offset);
                        let dest = match write_unique(out, &rel, &h.data) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        files.push(FileEntry {
                            out: dest.to_string_lossy().into_owned(),
                            source: "carve".to_string(),
                            bundle: bundle_name.clone(),
                            node: format!("carve@{:x}", h.offset),
                            offset: h.offset as u64,
                            size: h.data.len(),
                            sha256: sha256_hex(&h.data),
                            sig_ok: h.sig_ok,
                            sig_key: None,
                            kind: format!("carve-{:?}", h.kind),
                            lua_version: None,
                            module: None,
                            requires: if ext == "lua" {
                                pathmap::extract_requires(&h.data)
                            } else {
                                Vec::new()
                            },
                        });
                    }
                } else {
                    notes.push(format!("{bundle_name}: parse failed: {msg}"));
                }
            }
        }
    }
    Ok(Manifest {
        tool: "azur-promilia-lua-dumper".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        kind: "static".to_string(),
        files,
        notes,
    })
}

/// Handle one YooAsset raw blob (XOR-0x40 signed bytecode / JSON / text).
fn push_raw_hit(
    out: &Path,
    files: &mut Vec<FileEntry>,
    notes: &mut Vec<String>,
    input: &Path,
    bundle_name: &str,
    hit: raw::RawHit,
    decompile: bool,
) -> Result<()> {
    let (rel_base, module) = match &hit.chunk_path {
        Some(c) => {
            let (rel, module) = raw::chunk_identity(c);
            let stem = rel.strip_suffix(".lua").unwrap_or(&rel).to_string();
            (stem, module)
        }
        None => (format!("_raw/{bundle_name}"), None),
    };
    let (kind, ext) = match hit.kind {
        raw::RawKind::Bytecode => ("raw-bytecode", "lub"),
        raw::RawKind::Text => ("raw-text", "lua"),
        raw::RawKind::Json => ("raw-json", "json"),
        raw::RawKind::Other => ("raw-other", "bin"),
    };
    let mut entry = FileEntry {
        out: String::new(),
        source: "raw".to_string(),
        bundle: bundle_name.to_string(),
        node: input.to_string_lossy().into_owned(),
        offset: 0,
        size: hit.body.len(),
        sha256: sha256_hex(&hit.body),
        sig_ok: hit.sig_ok,
        sig_key: hit.sig_key.map(|k| k.as_str().to_string()),
        kind: kind.to_string(),
        lua_version: None,
        module,
        requires: Vec::new(),
    };
    if hit.kind == raw::RawKind::Bytecode {
        entry.lua_version = Some(decompile::classify_bytecode(&hit.body).as_str().to_string());
        let dest = write_unique(out, &format!("{rel_base}.{ext}"), &hit.body)?;
        entry.out = dest.to_string_lossy().into_owned();
        if decompile {
            match decompile::try_decompile(&hit.body, decompile::classify_bytecode(&hit.body)) {
                Ok(src) => {
                    let dec = write_unique(out, &format!("{rel_base}.lua"), src.as_bytes())?;
                    notes.push(format!("decompiled {} -> {}", entry.out, dec.display()));
                }
                Err(e) => notes.push(format!("{bundle_name}: decompile skipped: {e}")),
            }
        }
    } else {
        if hit.kind == raw::RawKind::Text {
            entry.requires = pathmap::extract_requires(&hit.body);
        }
        let dest = write_unique(out, &format!("{rel_base}.{ext}"), &hit.body)?;
        entry.out = dest.to_string_lossy().into_owned();
    }
    files.push(entry);
    Ok(())
}

fn do_mem(pid: u32, out: &Path, decompile: bool) -> Result<Manifest> {
    let mut files: Vec<FileEntry> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    mem::scan_pid(pid, |addr, hit| {
        let ext = match hit.kind {
            carve::CarveKind::Bytecode => "lub",
            _ => "lua",
        };
        let rel = format!("_mem/{addr:016x}.{ext}");
        let dest = write_unique(out, &rel, &hit.data)?;
        let mut entry = FileEntry {
            out: dest.to_string_lossy().into_owned(),
            source: "mem".to_string(),
            bundle: format!("pid:{pid}"),
            node: format!("mem@{addr:016x}"),
            offset: addr,
            size: hit.data.len(),
            sha256: sha256_hex(&hit.data),
            sig_ok: hit.sig_ok,
            sig_key: None,
            kind: format!("mem-{:?}", hit.kind),
            lua_version: None,
            module: None,
            requires: if ext == "lua" {
                pathmap::extract_requires(&hit.data)
            } else {
                Vec::new()
            },
        };
        if decompile && matches!(hit.kind, carve::CarveKind::Bytecode) {
            let flavor = decompile::classify_bytecode(&hit.data);
            entry.lua_version = Some(flavor.as_str().to_string());
            if let Ok(src) = decompile::try_decompile(&hit.data, flavor) {
                let rel = format!("_mem/{addr:016x}.lua");
                if let Ok(d) = write_unique(out, &rel, src.as_bytes()) {
                    entry.out = d.to_string_lossy().into_owned();
                }
            }
        }
        files.push(entry);
        Ok(())
    })?;
    notes.push("mem scan is read-only; key dumping is not implemented by design".to_string());
    Ok(Manifest {
        tool: "azur-promilia-lua-dumper".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        kind: "mem".to_string(),
        files,
        notes,
    })
}

fn do_recover(bundle: &Path, scans: &[PathBuf], exhaustive: bool) -> Result<()> {
    let data = std::fs::read(bundle).with_context(|| format!("read {}", bundle.display()))?;
    let (norm, variant) = decrypt::normalize(&data)?;
    println!("variant: {}", variant.as_str());
    let header = unityfs::Header::parse(&norm)?;
    println!(
        "header: version={} player={:?} engine={:?} flags=0x{:x} encrypted={}",
        header.version,
        header.player,
        header.engine,
        header.flags,
        header.encrypted()
    );
    let vecs = header
        .vectors
        .as_ref()
        .context("bundle is not UnityCN-encrypted; no key needed")?;
    println!("vectors: unknown_1=0x{:08x}", vecs.unknown_1);
    for scan in scans {
        println!("scanning {} ...", scan.display());
        let hay = std::fs::read(scan)
            .with_context(|| format!("read {}", scan.display()))?;
        match if exhaustive {
            unitycn::brute_force_key_exhaustive(&hay, &vecs.vec_key_sig, &vecs.vec_data_sig)
        } else {
            unitycn::brute_force_key(&hay, &vecs.vec_key_sig, &vecs.vec_data_sig)
        } {
            Some(k) => {
                println!("FOUND KEY in {}: {}", scan.display(), String::from_utf8_lossy(&k));
                println!("use as: --decrypt-key {}", String::from_utf8_lossy(&k));
                return Ok(());
            }
            None => println!("no key in {}", scan.display()),
        }
    }
    anyhow::bail!("key not found in scanned files")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Static { res, out, decrypt_key, decompile } => {
            let key = match decrypt_key {
                Some(s) => Some(parse_key(&s)?),
                None => DEFAULT_DECRYPT_KEY.map(|s| {
                    let mut k = [0u8; 16];
                    k.copy_from_slice(&s.as_bytes()[..16]);
                    k
                }),
            };
            if key.is_none() {
                eprintln!("note: no decrypt key; encrypted bundles fall back to carving");
            }
            std::fs::create_dir_all(&out)?;
            let manifest = do_static(&res, &out, key, decompile)?;
            std::fs::write(out.join("manifest.json"), serde_json::to_string_pretty(&manifest)?)?;
            println!(
                "done: {} files, {} notes -> {}",
                manifest.files.len(),
                manifest.notes.len(),
                out.join("manifest.json").display()
            );
            for n in manifest.notes.iter().take(20) {
                println!("  note: {n}");
            }
        }
        Cmd::Mem { pid, out, decompile } => {
            std::fs::create_dir_all(&out)?;
            let manifest = do_mem(pid, &out, decompile)?;
            std::fs::write(out.join("manifest.json"), serde_json::to_string_pretty(&manifest)?)?;
            println!(
                "done: {} hits -> {}",
                manifest.files.len(),
                out.join("manifest.json").display()
            );
        }
        Cmd::RecoverKey { bundle, scan, exhaustive } => {
            do_recover(&bundle, &scan, exhaustive)?;
        }
    }
    Ok(())
}
