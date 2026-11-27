//! One-shot inspector: header + blocks-info without the bundle password.

use azur_promilia_lua_dumper::decrypt;
use azur_promilia_lua_dumper::unityfs;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: inspect <bundle>");
    let data = std::fs::read(&path)?;
    let (norm, variant) = decrypt::normalize(&data)?;
    println!("variant: {}", variant.as_str());
    let header = unityfs::Header::parse(&norm)?;
    println!(
        "version={} player={:?} engine={:?} size={} cbi={} ubi={} flags=0x{:x} vectors@{}",
        header.version,
        header.player,
        header.engine,
        header.file_size,
        header.blocks_info_compressed,
        header.blocks_info_uncompressed,
        header.flags,
        header.blocks_info_offset
    );
    // Blocks-info itself needs no key (bundle flags 0x643 => 0x100 clear).
    let bundle = unityfs::Bundle::parse_metadata(&norm)?;
    println!(
        "blocks={} nodes={}",
        bundle.blocks.len(),
        bundle.nodes.len()
    );
    for b in bundle.blocks.iter().take(10) {
        println!(
            "  block unc={} comp={} flags=0x{:x} encrypted={}",
            b.uncompressed,
            b.compressed,
            b.flags,
            b.flags & 0x100 != 0
        );
    }
    let enc = bundle.blocks.iter().filter(|b| b.flags & 0x100 != 0).count();
    println!("encrypted blocks: {enc}/{}", bundle.blocks.len());
    for n in bundle.nodes.iter().take(40) {
        println!("  node off={} size={} flags={} {:?}", n.offset, n.size, n.flags, n.path);
    }
    Ok(())
}
