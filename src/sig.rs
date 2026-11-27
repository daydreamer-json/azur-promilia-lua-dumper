//! XLua RSA-1024 + SHA1 signature layer.
//!
//! `SignatureFile` prepends the 128-byte signature; `SignatureLoader`
//! throws on mismatch. The dumper verifies with the Lua key first,
//! falls back to the asset key, and records which key matched.
//! Both keys are PUBLICKEYBLOBs (safe to hardcode).

use anyhow::{Context, Result};
use crypto_bigint::{BoxedUint, Odd};
use rsa::PublicKey;
use sha1::{Digest, Sha1};

/// Signature length: RSA-1024 => 128 bytes, always prepended.
pub const SIG_LEN: usize = 128;

/// `SignatureUtility.KEY` (dump.cs). Asset-side public key.
pub const ASSET_PUBKEY_B64: &str = "BgIAAACkAABSU0ExAAQAAAEAAQCPW2f86y+8DUfEbmgnX9j9y2spXfrbRhYC9Zg2lHlWvfuAyPSwVYp9PW2evL/EZMRvZHzrVhR+n8ypDVoxenxqRMhxjroRJmlp7ZojwGHQ7fl6vra0tPkRMnuHW21cLqtdaDznTamKPCkavkSiPXz/egN6GZxM8X/5wGpaz8Dbng==";
/// `LuaManager.key` (stringliteral @0x1106C4E0). Lua-side public key.
pub const LUA_PUBKEY_B64: &str = "BgIAAACkAABSU0ExAAQAAAEAAQAlKpffOBg29Uk1yr5lngawEc2YBoPL+DyL/a7gfiKjuoTNUWBcdElhrBnc8uCXmmM4KWhTwlXrvROBxgD678OHOdkrFJujh3ZurxJsz7GeAhBSBPzRwsczlj6dI981KKO28iMgEFSqT6ELb4s/zHOA66XlWCEt+ljcaS1xnu4Unw==";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsed {
    Lua,
    Asset,
}

impl KeyUsed {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyUsed::Lua => "lua",
            KeyUsed::Asset => "asset",
        }
    }
}

/// Parsed RSA-1024 key: validated public key plus raw operands.
pub struct ParsedKey {
    pub public: PublicKey,
    pub n: BoxedUint,
    pub e: BoxedUint,
}

/// Parse a CSP PUBLICKEYBLOB (RSA1) into an RSA public key.
pub fn parse_csp_blob_b64(b64: &str) -> Result<ParsedKey> {
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("base64 pubkey")?;
    if blob.len() < 16 {
        anyhow::bail!("blob too short");
    }
    // BLOBHEADER: type(1)=6 PUBLICKEYBLOB, ver(1)=2, reserved(2)=0, algid(4)=0xA400.
    if blob[0] != 6 || blob[1] != 2 {
        anyhow::bail!("not a PUBLICKEYBLOB");
    }
    // RSAPUBKEY: magic "RSA1" LE, bitlen LE, pubexp LE.
    if &blob[8..12] != b"RSA1" {
        anyhow::bail!("not an RSA1 blob");
    }
    let bitlen = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
    if bitlen != 1024 {
        anyhow::bail!("expected RSA-1024, got {bitlen}");
    }
    let explen = 4usize;
    let modlen = bitlen / 8;
    if blob.len() < 16 + explen + modlen {
        anyhow::bail!("truncated modulus");
    }
    let exp = u32::from_le_bytes(blob[16..20].try_into().unwrap());
    let mut mod_be = blob[20..20 + modlen].to_vec();
    mod_be.reverse(); // LE -> BE
    let n =
        BoxedUint::from_be_slice(&mod_be, 1024).map_err(|e| anyhow::anyhow!("modulus: {e:?}"))?;
    let e = BoxedUint::from_be_slice(&exp.to_be_bytes(), 1024)
        .map_err(|e| anyhow::anyhow!("exponent: {e:?}"))?;
    let public =
        PublicKey::new(n.clone(), e.clone()).map_err(|e| anyhow::anyhow!("rsa key: {e}"))?;
    Ok(ParsedKey { public, n, e })
}

/// PKCS#1 v1.5 (SHA-1) verification done manually to avoid
/// digest-OID trait plumbing: EM = 00 01 FF..FF 00 DigestInfo.
pub fn verify_pkcs1v15_sha1(key: &ParsedKey, sig: &[u8], body: &[u8]) -> bool {
    if sig.len() != 128 {
        return false;
    }
    const PREFIX: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
        0x14,
    ];
    let hash = Sha1::digest(body);
    let mut em = vec![0u8; 128];
    em[0] = 0x00;
    em[1] = 0x01;
    let ps_len = 128 - 3 - PREFIX.len() - hash.len();
    for b in em[2..2 + ps_len].iter_mut() {
        *b = 0xFF;
    }
    em[2 + ps_len] = 0x00;
    em[2 + ps_len + 1..2 + ps_len + 1 + PREFIX.len()].copy_from_slice(PREFIX);
    em[2 + ps_len + 1 + PREFIX.len()..].copy_from_slice(&hash);
    let odd_n = match Option::from(Odd::new(key.n.clone())) {
        Some(o) => o,
        None => return false,
    };
    let s = match BoxedUint::from_be_slice(sig, 1024) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let m = s.pow_mod(&key.e, &odd_n);
    let mut got = m.to_be_bytes().into_vec();
    // Left-pad to 128 bytes (BoxedUint strips leading zeros).
    if got.len() > 128 {
        return false;
    }
    let mut full = vec![0u8; 128 - got.len()];
    full.append(&mut got);
    full == em
}
/// Verify `data` (sig + body). Returns the body and which key matched.
/// `None` (Ok) means "no signature / mismatch" rather than an error.
pub fn verify(data: &[u8]) -> Result<Option<(Vec<u8>, KeyUsed)>> {
    if data.len() < SIG_LEN {
        return Ok(None);
    }
    let (sig, body) = data.split_at(SIG_LEN);
    for (b64, used) in [(LUA_PUBKEY_B64, KeyUsed::Lua), (ASSET_PUBKEY_B64, KeyUsed::Asset)] {
        let key = parse_csp_blob_b64(b64)?;
        if verify_pkcs1v15_sha1(&key, sig, body) {
            return Ok(Some((body.to_vec(), used)));
        }
    }
    Ok(None)
}

/// Strip a UTF-8 BOM if present. Mirrors `CleanUTF8Bom`.
pub fn strip_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data)
}

/// Convenience: verify, fall back to raw body; always strips BOM.
pub struct Stripped {
    pub body: Vec<u8>,
    pub sig_ok: bool,
    pub key: Option<KeyUsed>,
}

pub fn strip(data: &[u8]) -> Result<Stripped> {
    match verify(data)? {
        Some((body, key)) => Ok(Stripped {
            body: strip_bom(&body).to_vec(),
            sig_ok: true,
            key: Some(key),
        }),
        None => Ok(Stripped {
            body: strip_bom(data).to_vec(),
            sig_ok: false,
            key: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardcoded_keys_parse_as_rsa1024() {
        for b64 in [LUA_PUBKEY_B64, ASSET_PUBKEY_B64] {
            let k = parse_csp_blob_b64(b64).unwrap();
            assert_eq!(k.n.bit_width(), 1024);
        }
        assert_ne!(LUA_PUBKEY_B64, ASSET_PUBKEY_B64);
    }

    #[test]
    fn garbage_has_no_sig() {
        assert!(verify(b"short").unwrap().is_none());
        let blob = vec![0xAAu8; 512];
        assert!(verify(&blob).unwrap().is_none());
    }

    #[test]
    fn strip_keeps_bom_logic() {
        let s = strip(b"\xEF\xBB\xBFreturn 1").unwrap();
        assert!(!s.sig_ok);
        assert_eq!(s.body, b"return 1");
    }
}
