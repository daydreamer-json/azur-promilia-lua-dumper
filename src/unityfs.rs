//! Minimal UnityFS (Unity 2022, header version 6-8) reader.
//!
//! Handles: combined blocks+directory info, LZ4/LZ4HC blocks, 16-byte
//! alignment, UnityCN block decryption (0x400) via [`crate::unitycn`].
//! LZMA blocks are reported as unsupported (`shortcut:` below).

use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

use crate::unitycn::Decryptor;

pub const FLAG_COMPRESSION_MASK: u32 = 0x3F;
pub const FLAG_COMBINED: u32 = 0x40;
pub const FLAG_AT_END: u32 = 0x80;
pub const FLAG_PADDING: u32 = 0x200;
/// UnityCN/Tuanjie block encryption bit (new flag set).
pub const FLAG_UNITYCN: u32 = 0x400;

/// Header vectors needed to key the UnityCN decryptor.
#[derive(Debug, Clone)]
pub struct CnVectors {
    pub unknown_1: u32,
    pub vec_data: [u8; 16],
    pub vec_key: [u8; 16],
    pub vec_data_sig: [u8; 16],
    pub vec_key_sig: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u32,
    pub player: String,
    pub engine: String,
    pub file_size: i64,
    pub blocks_info_compressed: u32,
    pub blocks_info_uncompressed: u32,
    pub flags: u32,
    /// Offset where the blocks-info section starts (post vectors/align).
    pub blocks_info_offset: usize,
    pub vectors: Option<CnVectors>,
}

#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub uncompressed: u32,
    pub compressed: u32,
    pub flags: u16,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub offset: u64,
    pub size: u64,
    pub flags: u32,
    pub path: String,
}

fn read_cstr(cur: &mut Cursor<&[u8]>) -> Result<String> {
    let mut buf = Vec::new();
    loop {
        let mut b = [0u8; 1];
        cur.read_exact(&mut b).context("header cstr")?;
        if b[0] == 0 {
            break;
        }
        buf.push(b[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn align16(pos: usize) -> usize {
    (pos + 15) & !15
}

impl Header {
    pub fn parse(data: &[u8]) -> Result<Header> {
        let mut cur = Cursor::new(data);
        let mut sig = [0u8; 8];
        cur.read_exact(&mut sig).context("sig")?;
        if &sig[..7] != b"UnityFS" || sig[7] != 0 {
            bail!("not a UnityFS bundle");
        }
        let version = cur.read_u32::<BigEndian>()?;
        let player = read_cstr(&mut cur)?;
        let engine = read_cstr(&mut cur)?;
        let file_size = cur.read_i64::<BigEndian>()?;
        let cbi = cur.read_u32::<BigEndian>()?;
        let ubi = cur.read_u32::<BigEndian>()?;
        let flags = cur.read_u32::<BigEndian>()?;
        let mut pos = cur.position() as usize;
        if version >= 7 {
            pos = align16(pos);
        }
        let mut vectors = None;
        if flags & FLAG_UNITYCN != 0 {
            // Observed layout (game v1.0.1, all bundles share it):
            // u32 unknown_1 + data[16] + key[16] + data_sig[16] + key_sig[16]
            // then zero padding up to 16-byte alignment.
            // (UnityPy's +1 inter-vector pad bytes do not exist here.)
            let r = &data[pos..];
            if r.len() < 68 {
                bail!("truncated UnityCN vectors");
            }
            let unknown_1 = u32::from_be_bytes(r[0..4].try_into().unwrap());
            let mut vec_data = [0u8; 16];
            let mut vec_key = [0u8; 16];
            let mut vec_data_sig = [0u8; 16];
            let mut vec_key_sig = [0u8; 16];
            vec_data.copy_from_slice(&r[4..20]);
            vec_key.copy_from_slice(&r[20..36]);
            vec_data_sig.copy_from_slice(&r[36..52]);
            vec_key_sig.copy_from_slice(&r[52..68]);
            let _ = unknown_1;
            vectors = Some(CnVectors {
                unknown_1,
                vec_data,
                vec_key,
                vec_data_sig,
                vec_key_sig,
            });
            pos = align16(pos + 68);
        }
        Ok(Header {
            version,
            player,
            engine,
            file_size,
            blocks_info_compressed: cbi,
            blocks_info_uncompressed: ubi,
            flags,
            blocks_info_offset: pos,
            vectors,
        })
    }

    pub fn encrypted(&self) -> bool {
        self.flags & FLAG_UNITYCN != 0
    }
}

fn decompress_block_bytes(data: &[u8], uncompressed: u32, comp: u32) -> Result<Vec<u8>> {
    match comp {
        0 => Ok(data.to_vec()),
        2 | 3 => {
            // shortcut: lz4_flex errors surface as-is; ubi from header is the bound.
            // If exact-size decompress fails, fall back to unbounded prefix mode.
            lz4_flex::block::decompress(data, uncompressed as usize)
                .or_else(|_| lz4_flex::decompress_size_prepended(data))
                .map_err(|e| anyhow::anyhow!("lz4 decompress: {e}"))
        }
        1 => bail!("shortcut: LZMA blocks unsupported, needs lzma crate + re-test"),
        _ => bail!("unknown compression {comp}"),
    }
}

pub struct Bundle {
    pub header: Header,
    pub blocks: Vec<BlockInfo>,
    pub nodes: Vec<Node>,
    /// Concatenated uncompressed block payload.
    pub payload: Vec<u8>,
}

impl Bundle {
    /// Parse header + blocks-info + directory only (no key, no payload).
    pub fn parse_metadata(data: &[u8]) -> Result<Bundle> {
        let header = Header::parse(data)?;

        // Blocks-info location.
        let (bi_bytes_raw, data_start_hint) = if header.flags & FLAG_AT_END != 0 {
            let start = data
                .len()
                .checked_sub(header.blocks_info_compressed as usize)
                .context("blocks-info at end OOB")?;
            (&data[start..], 0usize)
        } else {
            let s = header.blocks_info_offset;
            let e = s + header.blocks_info_compressed as usize;
            (data.get(s..e).context("blocks-info OOB")?, e)
        };
        let bi_comp = header.flags & FLAG_COMPRESSION_MASK;
        let bi_bytes = decompress_block_bytes(bi_bytes_raw, header.blocks_info_uncompressed, bi_comp)
            .context("blocks-info decompress")?;

        let mut cur = Cursor::new(&bi_bytes[..]);
        let mut hash = [0u8; 16];
        cur.read_exact(&mut hash)?;
        let nblocks = cur.read_i32::<BigEndian>()?;
        if nblocks < 0 || nblocks > 1_000_000 {
            bail!("insane block count {nblocks}");
        }
        let mut blocks = Vec::with_capacity(nblocks as usize);
        for _ in 0..nblocks {
            blocks.push(BlockInfo {
                uncompressed: cur.read_u32::<BigEndian>()?,
                compressed: cur.read_u32::<BigEndian>()?,
                flags: cur.read_u16::<BigEndian>()?,
            });
        }
        let nnodes = cur.read_i32::<BigEndian>()?;
        if nnodes < 0 || nnodes > 4_000_000 {
            bail!("insane node count {nnodes}");
        }
        let mut nodes = Vec::with_capacity(nnodes as usize);
        for _ in 0..nnodes {
            let offset = cur.read_u64::<BigEndian>()?;
            let size = cur.read_u64::<BigEndian>()?;
            let flags = cur.read_u32::<BigEndian>()?;
            let path = read_cstr(&mut cur)?;
            nodes.push(Node { offset, size, flags, path });
        }
        let _ = data_start_hint;
        Ok(Bundle { header, blocks, nodes, payload: Vec::new() })
    }

    /// Payload start offset in `data` (post header/vectors/blocks-info).
    fn payload_start(data: &[u8], meta: &Bundle) -> Result<usize> {
        let header = &meta.header;
        if header.flags & FLAG_AT_END != 0 {
            Ok(if header.flags & FLAG_PADDING != 0 {
                align16(header.blocks_info_offset)
            } else {
                header.blocks_info_offset
            })
        } else {
            let mut pos = header.blocks_info_offset + header.blocks_info_compressed as usize;
            if header.flags & FLAG_PADDING != 0 {
                pos = align16(pos);
            }
            if pos > data.len() {
                bail!("payload start OOB");
            }
            Ok(pos)
        }
    }

    pub fn parse(data: &[u8], password: Option<&[u8; 16]>) -> Result<Bundle> {
        let mut meta = Bundle::parse_metadata(data)?;
        let header = meta.header.clone();
        let decryptor = match (&header.vectors, password) {
            (Some(v), Some(p)) => Some(Decryptor::new(p, &v.vec_key, &v.vec_data)),
            (Some(_), None) => bail!("bundle is UnityCN-encrypted; supply --decrypt-key or run recover-key"),
            _ => None,
        };

        let payload_end = if header.flags & FLAG_AT_END != 0 {
            data.len()
                .checked_sub(header.blocks_info_compressed as usize)
                .context("payload end OOB")?
        } else {
            data.len()
        };
        let mut payload = Vec::new();
        let mut p = Bundle::payload_start(data, &meta)?;
        for (i, b) in meta.blocks.iter().enumerate() {
            let e = p + b.compressed as usize;
            if e > payload_end {
                bail!("block {i} OOB");
            }
            let mut raw = data[p..e].to_vec();
            if b.flags & 0x100 != 0 {
                let d = decryptor
                    .as_ref()
                    .context("encrypted block but no decryptor")?;
                raw = d.decrypt_block(&raw, i as u32);
            }
            payload.extend_from_slice(&decompress_block_bytes(
                &raw,
                b.uncompressed,
                (b.flags & 0x3F) as u32,
            )?);
            p = e;
        }
        meta.payload = payload;
        Ok(meta)
    }

    /// Slice a node out of the concatenated payload.
    pub fn node_bytes<'a>(&self, payload: &'a [u8], node: &Node) -> Result<&'a [u8]> {
        let s = node.offset as usize;
        let e = s + node.size as usize;
        payload.get(s..e).context("node OOB").map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_bundle() -> Vec<u8> {
        // Build a minimal unencrypted UnityFS: 1 LZ4 block holding "hello-lua".
        let payload = b"return {hello=1}".to_vec();
        let comp = lz4_flex::block::compress(&payload);
        let mut bi = Vec::new();
        bi.extend_from_slice(&[0u8; 16]);
        bi.extend_from_slice(&1i32.to_be_bytes());
        bi.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bi.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        bi.extend_from_slice(&2u16.to_be_bytes()); // LZ4, no 0x100
        bi.extend_from_slice(&1i32.to_be_bytes());
        bi.extend_from_slice(&0u64.to_be_bytes());
        bi.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        bi.extend_from_slice(&0u32.to_be_bytes());
        bi.extend_from_slice(b"Assets/Lua/64/src/hello.bytes\0");
        let bi_comp = lz4_flex::block::compress(&bi);
        let mut out = Vec::new();
        out.extend_from_slice(b"UnityFS\0");
        out.extend_from_slice(&7u32.to_be_bytes());
        out.extend_from_slice(b"2022.3.62f3\0");
        out.extend_from_slice(b"0.0.0\0");
        out.extend_from_slice(&0i64.to_be_bytes());
        out.extend_from_slice(&(bi_comp.len() as u32).to_be_bytes());
        out.extend_from_slice(&(bi.len() as u32).to_be_bytes());
        out.extend_from_slice(&0x243u32.to_be_bytes()); // combined|padding|lz4hc
        while out.len() % 16 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&bi_comp);
        while out.len() % 16 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&comp);
        out
    }

    #[test]
    fn parse_synthetic() {
        let data = synthetic_bundle();
        let b = Bundle::parse(&data, None).unwrap();
        assert_eq!(b.nodes.len(), 1);
        let nb = b.node_bytes(&b.payload, &b.nodes[0]).unwrap();
        assert_eq!(nb, b"return {hello=1}");
    }

    #[test]
    fn rejects_garbage() {
        assert!(Header::parse(b"nope").is_err());
    }
}
