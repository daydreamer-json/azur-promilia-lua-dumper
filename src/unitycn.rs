//! UnityCN (Tuanjie) AssetBundle block decryption.
//!
//! Format reference (MIT, behavior source): K0lb3/UnityPy
//! `helpers/ArchiveStorageManager.py` + `enums/BundleFile.py`.
//! Bundles built with `ChunkBasedCompression | EnableProtection` set
//! `ArchiveFlags = 0x643` (LZ4HC | Combined | Padding | UnityCN 0x400).

use aes::Aes128;
use aes::cipher::{Block, BlockCipherEncrypt, Key, KeyInit};

/// Magic the decrypted header signature must equal.
pub const UNITY3D_SIGNATURE: &[u8; 16] = b"#$unity3dchina!@";

/// Length of a UnityCN bundle password (128 bit, 16 ASCII chars).
pub const KEY_LEN: usize = 16;

/// AES-128-ECB encrypt one block, then XOR with `data`.
///
/// Mirrors UnityPy `decrypt_key(key, data, keybytes)`.
pub fn xor_with_aes(key_sig: &[u8; 16], data_sig: &[u8; 16], password: &[u8; 16]) -> [u8; 16] {
    let mut key = Key::<Aes128>::default();
    key.copy_from_slice(password);
    let cipher = Aes128::new(&key);
    let mut block = Block::<Aes128>::default();
    block.copy_from_slice(key_sig);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = data_sig[i] ^ block[i];
    }
    out
}

/// Check whether `password` is the bundle decrypt key for the given vectors.
pub fn validate_key(password: &[u8; 16], key_sig: &[u8; 16], data_sig: &[u8; 16]) -> bool {
    xor_with_aes(key_sig, data_sig, password) == *UNITY3D_SIGNATURE
}

/// Per-bundle stream-cipher tables derived from the header vectors.
#[derive(Debug, Clone)]
pub struct Decryptor {
    index: [u8; 16],
    substitute: [u8; 16],
}

impl Decryptor {
    /// Derive tables. Mirrors `ArchiveStorageDecryptor.__init__` tail.
    pub fn new(password: &[u8; 16], vec_key: &[u8; 16], vec_data: &[u8; 16]) -> Self {
        let raw = xor_with_aes(vec_key, vec_data, password);
        // Nibble-split each byte into (high, low).
        let mut nibbles = [0u8; 32];
        for (i, b) in raw.iter().enumerate() {
            nibbles[2 * i] = b >> 4;
            nibbles[2 * i + 1] = b & 0xF;
        }
        let mut index = [0u8; 16];
        index.copy_from_slice(&nibbles[..16]);
        // substitute[j][i] layout transposed: sub[j + 4*i]... port literally:
        // substitute = bytes(data[0x10 + i*4 + j] for j in range(4) for i in range(4))
        let mut substitute = [0u8; 16];
        for j in 0..4 {
            for i in 0..4 {
                substitute[j * 4 + i] = nibbles[0x10 + i * 4 + j];
            }
        }
        Self { index, substitute }
    }

    fn decrypt_byte(&self, data: &mut [u8], offset: usize, index: u32) -> (u8, usize, u32) {
        let b = self.substitute[(((index >> 2) & 3) + 4) as usize] as i32
            + self.substitute[(index & 3) as usize] as i32
            + self.substitute[(((index >> 4) & 3) + 8) as usize] as i32
            + self.substitute[(((index % 256) >> 6) + 12) as usize] as i32;
        let lo = (self.index[(data[offset] & 0xF) as usize] as i32 - b) & 0xF;
        let hi = self.index[(data[offset] >> 4) as usize] as i32 - b;
        data[offset] = (lo | (0x10 * hi)).rem_euclid(256) as u8;
        (data[offset], offset + 1, index + 1)
    }

    /// Mirrors `ArchiveStorageDecryptor.decrypt`.
    /// Returns the consumed byte count (relative to `data` start).
    /// Out-of-range reads stop the walk instead of panicking.
    fn decrypt_walk(&self, data: &mut [u8], mut index: u32, remaining: usize) -> usize {
        let mut offset = 0usize;
        let (cur, o, i) = match self.step(data, offset, index) {
            Some(v) => v,
            None => return remaining,
        };
        offset = o;
        index = i;
        let mut byte_high = (cur >> 4) as i32;
        let byte_low = (cur & 0xF) as i32;
        if byte_high == 0xF {
            let mut b = 0xFFu8;
            while b == 0xFF {
                match self.step(data, offset, index) {
                    Some((nb, o, i)) => {
                        b = nb;
                        offset = o;
                        index = i;
                    }
                    None => return remaining,
                }
                byte_high += b as i32;
            }
        }
        offset = offset.saturating_add(byte_high.max(0) as usize);
        if offset < remaining {
            for _ in 0..2 {
                match self.step(data, offset, index) {
                    Some((_, o, i)) => {
                        offset = o;
                        index = i;
                    }
                    None => return remaining,
                }
            }
            if byte_low == 0xF {
                let mut b = 0xFFu8;
                while b == 0xFF {
                    match self.step(data, offset, index) {
                        Some((nb, o, i)) => {
                            b = nb;
                            offset = o;
                            index = i;
                        }
                        None => return remaining,
                    }
                }
            }
        }
        offset.min(remaining)
    }

    fn step(&self, data: &mut [u8], offset: usize, index: u32) -> Option<(u8, usize, u32)> {
        if offset >= data.len() {
            return None;
        }
        Some(self.decrypt_byte(data, offset, index))
    }

    /// Decrypt one compressed block. Mirrors `decrypt_block`.
    pub fn decrypt_block(&self, data: &[u8], mut block_index: u32) -> Vec<u8> {
        let mut out = data.to_vec();
        let mut offset = 0usize;
        let total = out.len();
        while offset < total {
            let consumed = self.decrypt_walk(&mut out[offset..], block_index, total - offset);
            if consumed == 0 {
                break;
            }
            offset += consumed;
            block_index += 1;
        }
        out
    }
}

/// Scan `haystack` for 16-char word candidates (ASCII and UTF-16LE),
/// testing each against the header vectors. Returns the first hit.
pub fn brute_force_key(
    haystack: &[u8],
    key_sig: &[u8; 16],
    data_sig: &[u8; 16],
) -> Option<[u8; 16]> {
    // ASCII [A-Za-z0-9_]{16} runs.
    if let Some(k) = scan_ascii(haystack, key_sig, data_sig) {
        return Some(k);
    }
    scan_utf16le(haystack, key_sig, data_sig)
}

/// Exhaustive scan: every 16-byte window (any bytes) + every UTF-16LE
/// window. Slow (one AES op per offset) but finds keys with symbols.
/// Prints progress to stderr.
pub fn brute_force_key_exhaustive(
    haystack: &[u8],
    key_sig: &[u8; 16],
    data_sig: &[u8; 16],
) -> Option<[u8; 16]> {
    if haystack.len() >= 16 {
        for (i, w) in haystack.windows(16).enumerate() {
            if i % (64 * 1024 * 1024) == 0 {
                eprintln!("  ... {} MiB", i / (1024 * 1024));
            }
            let mut cand = [0u8; 16];
            cand.copy_from_slice(w);
            if validate_key(&cand, key_sig, data_sig) {
                return Some(cand);
            }
        }
    }
    eprintln!("  ... ascii pass done, utf16 pass");
    // UTF-16LE: 16 consecutive units, high byte 0, low byte anything.
    let units = haystack.len() / 2;
    let mut i = 0;
    while i + 16 <= units {
        if i % (64 * 1024 * 1024) == 0 {
            eprintln!("  ... {} MiB-units", i / (1024 * 1024));
        }
        let mut cand = [0u8; 16];
        let mut ok = true;
        for k in 0..16 {
            let lo = haystack[(i + k) * 2];
            let hi = haystack[(i + k) * 2 + 1];
            if hi != 0 {
                ok = false;
                break;
            }
            cand[k] = lo;
        }
        if ok && validate_key(&cand, key_sig, data_sig) {
            return Some(cand);
        }
        i += 1;
    }
    None
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn scan_ascii(haystack: &[u8], key_sig: &[u8; 16], data_sig: &[u8; 16]) -> Option<[u8; 16]> {
    // Overlapping windows would be O(n) AES ops; restrict to runs to stay fast,
    // then test every 16-wide window inside runs longer than 16.
    let mut i = 0;
    let mut tested = std::collections::HashSet::new();
    while i < haystack.len() {
        if !is_word_byte(haystack[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < haystack.len() && is_word_byte(haystack[i]) {
            i += 1;
        }
        let run = &haystack[start..i];
        if run.len() < 16 {
            continue;
        }
        for off in 0..=run.len() - 16 {
            let mut cand = [0u8; 16];
            cand.copy_from_slice(&run[off..off + 16]);
            if !tested.insert(cand) {
                continue;
            }
            if validate_key(&cand, key_sig, data_sig) {
                return Some(cand);
            }
        }
    }
    None
}

fn scan_utf16le(haystack: &[u8], key_sig: &[u8; 16], data_sig: &[u8; 16]) -> Option<[u8; 16]> {
    // Look for 16 consecutive ASCII-word UTF-16LE code units.
    let units = haystack.len() / 2;
    let mut i = 0;
    let mut tested = std::collections::HashSet::new();
    let at = |idx: usize| -> Option<u8> {
        let lo = *haystack.get(idx * 2)?;
        let hi = *haystack.get(idx * 2 + 1)?;
        (hi == 0).then_some(lo)
    };
    while i < units {
        match at(i) {
            Some(c) if is_word_byte(c) => {
                let start = i;
                while let Some(c) = at(i) {
                    if !is_word_byte(c) {
                        break;
                    }
                    i += 1;
                }
                let len = i - start;
                if len >= 16 {
                    for off in 0..=len - 16 {
                        let mut cand = [0u8; 16];
                        for (k, u) in cand.iter_mut().enumerate() {
                            *u = at(start + off + k).unwrap_or(0);
                        }
                        if !tested.insert(cand) {
                            continue;
                        }
                        if validate_key(&cand, key_sig, data_sig) {
                            return Some(cand);
                        }
                    }
                }
            }
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_roundtrip_self_consistent() {
        let pwd = *b"0123456789abcdef";
        let ks = *b"0123456789ABCDEF";
        let ds = *b"fedcba9876543210";
        // validate_key is false for random vectors, but must not panic;
        // and xor_with_aes must be deterministic.
        let a = xor_with_aes(&ks, &ds, &pwd);
        let b = xor_with_aes(&ks, &ds, &pwd);
        assert_eq!(a, b);
        assert!(!validate_key(&pwd, &ks, &ds));
    }

    #[test]
    fn decrypt_block_is_deterministic_and_sized() {
        let pwd = *b"0123456789abcdef";
        let d = Decryptor::new(&pwd, &[1u8; 16], &[2u8; 16]);
        let data = vec![0xABu8; 256];
        let o1 = d.decrypt_block(&data, 0);
        let o2 = d.decrypt_block(&data, 0);
        assert_eq!(o1, o2);
        assert_eq!(o1.len(), data.len());
    }

    #[test]
    fn brute_force_finds_ascii_key() {
        // Build vectors for a known password, then scan a blob containing it.
        let pwd = *b"TestKey123456789";
        // Fake vectors: pick key_sig random, data_sig = AES(pwd, key_sig) xor SIG.
        let mut key = Key::<Aes128>::default();
        key.copy_from_slice(&pwd);
        let cipher = Aes128::new(&key);
        let mut enc = Block::<Aes128>::default();
        enc.copy_from_slice(b"0123456789ABCDEF");
        cipher.encrypt_block(&mut enc);
        let mut ds = [0u8; 16];
        for i in 0..16 {
            ds[i] = UNITY3D_SIGNATURE[i] ^ enc[i];
        }
        let ks = *b"0123456789ABCDEF";
        let mut hay = b"xxxx noise \0\xff TestKey123456789 trailing".to_vec();
        assert_eq!(brute_force_key(&hay, &ks, &ds), Some(pwd));
        hay = b"no key here at all..............".to_vec();
        assert_eq!(brute_force_key(&hay, &ks, &ds), None);
    }
}
