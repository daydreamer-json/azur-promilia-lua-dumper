//! YooAsset transfer layer: 32-byte offset + XOR 0x40.
//!
//! Local `.res` files are plain `UnityFS` (offset already stripped,
//! XOR already undone by the downloader). CDN payloads add a 32-byte
//! zero header and XOR the whole file with `BundleStream::KEY`.
//! Detection is automatic: pick the first variant whose head is `UnityFS`.

use anyhow::Result;

pub const BUNDLE_MAGIC: &[u8] = b"UnityFS";
pub const STREAM_XOR_KEY: u8 = 0x40;
pub const FILE_OFFSET: usize = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Raw,
    Xor40,
    Skip32,
    Skip32Xor40,
}

impl Variant {
    pub fn as_str(self) -> &'static str {
        match self {
            Variant::Raw => "raw",
            Variant::Xor40 => "xor40",
            Variant::Skip32 => "skip32",
            Variant::Skip32Xor40 => "skip32+xor40",
        }
    }
}

/// Normalize `data` to a plain UnityFS image. Returns owned bytes + variant.
pub fn normalize(data: &[u8]) -> Result<(Vec<u8>, Variant)> {
    if let Some(rest) = data.strip_prefix(BUNDLE_MAGIC) {
        let _ = rest;
        return Ok((data.to_vec(), Variant::Raw));
    }
    if data.len() > BUNDLE_MAGIC.len() {
        let xored: Vec<u8> = data.iter().map(|b| b ^ STREAM_XOR_KEY).collect();
        if xored.starts_with(BUNDLE_MAGIC) {
            return Ok((xored, Variant::Xor40));
        }
    }
    if data.len() > FILE_OFFSET && data[FILE_OFFSET..].starts_with(BUNDLE_MAGIC) {
        return Ok((data[FILE_OFFSET..].to_vec(), Variant::Skip32));
    }
    if data.len() > FILE_OFFSET + BUNDLE_MAGIC.len() {
        let xored: Vec<u8> = data[FILE_OFFSET..].iter().map(|b| b ^ STREAM_XOR_KEY).collect();
        if xored.starts_with(BUNDLE_MAGIC) {
            return Ok((xored, Variant::Skip32Xor40));
        }
    }
    anyhow::bail!("not a UnityFS image in any known YooAsset variant")
}

/// AKPK (Lens raw container) magic used by `raw_base_package`.
pub const AKPK_MAGIC: &[u8] = b"AKPK";

pub fn is_akpk(data: &[u8]) -> bool {
    data.starts_with(AKPK_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_roundtrip() {
        let mut raw = b"UnityFS\0payload-data-here".to_vec();
        let (n, v) = normalize(&raw).unwrap();
        assert_eq!(v, Variant::Raw);
        assert_eq!(n, raw);

        let xored: Vec<u8> = raw.iter().map(|b| b ^ STREAM_XOR_KEY).collect();
        let (n, v) = normalize(&xored).unwrap();
        assert_eq!(v, Variant::Xor40);
        assert_eq!(n, raw);

        let mut shifted = vec![0u8; FILE_OFFSET];
        shifted.append(&mut raw.clone());
        let (n, v) = normalize(&shifted).unwrap();
        assert_eq!(v, Variant::Skip32);
        assert_eq!(n, raw);

        let shifted_xor: Vec<u8> = shifted.iter().map(|b| b ^ STREAM_XOR_KEY).collect();
        let (n, v) = normalize(&shifted_xor).unwrap();
        assert_eq!(v, Variant::Skip32Xor40);
        assert_eq!(n, raw);

        assert!(normalize(b"garbage").is_err());
    }
}
