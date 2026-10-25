//! Software encryption (spec: "Encryption"): keybags, password unlock and AES-XTS decryption.
//! The DER layout of the wrapped-key blobs isn't in Apple's spec; it was read off real images.

use crate::container::{Container, checksum_ok};
use crate::{bad, slice, u16le, u32le, u64le};
use aes::Aes128;
use aes::cipher::KeyInit;
use sha2::{Digest, Sha256};
use std::io;
use xts_mode::{Xts128, get_tweak_default};

const KB_TAG_VOLUME_KEY: u16 = 2;
const KB_TAG_VOLUME_UNLOCK_RECORDS: u16 = 3;
const OBJECT_TYPE_CONTAINER_KEYBAG: u32 = 0x6b65_7973; // 'keys'
const OBJECT_TYPE_VOLUME_KEYBAG: u32 = 0x7265_6373; // 'recs'

/// A keybag entry: (owner uuid, KB_TAG_*, key data).
type KeybagEntry<'a> = ([u8; 16], u16, &'a [u8]);

/// AES-XTS-128 with a 32-byte key (two AES-128 keys). APFS encrypts in 512-byte units, tweaked by sector number.
pub(crate) struct Xts(Xts128<Aes128>);

impl Xts {
    pub(crate) fn new(key: &[u8]) -> io::Result<Xts> {
        let k = slice(key, 0, 32)?;
        let c1 = Aes128::new_from_slice(&k[..16]).map_err(|_| bad("bad AES key"))?;
        let c2 = Aes128::new_from_slice(&k[16..]).map_err(|_| bad("bad AES key"))?;
        Ok(Xts(Xts128::new(c1, c2)))
    }

    /// Decrypts `buf` in place; `sector` is the tweak of its first 512-byte unit.
    pub(crate) fn decrypt(&self, buf: &mut [u8], sector: u64) {
        self.0.decrypt_area(buf, 512, sector as u128, get_tweak_default);
    }

    /// Encrypts `buf` in place; `sector` is the tweak of its first 512-byte unit.
    pub(crate) fn encrypt(&self, buf: &mut [u8], sector: u64) {
        self.0.encrypt_area(buf, 512, sector as u128, get_tweak_default);
    }
}

/// Derives the volume encryption key from a user password (spec: "Accessing Encrypted Objects").
pub(crate) fn unlock_volume(c: &Container, vol_sb: &[u8], password: &str) -> io::Result<Xts> {
    let sb = &c.superblock;
    let vol_uuid = &vol_sb[240..256];
    let mine = |e: &&KeybagEntry| e.0 == vol_uuid;

    let ckb = read_keybag(c, u64le(sb, 1296), u64le(sb, 1304), &sb[72..88], OBJECT_TYPE_CONTAINER_KEYBAG)?;
    let centries = keybag_entries(&ckb)?;
    let find = |tag| {
        centries
            .iter()
            .filter(mine)
            .find(|e| e.1 == tag)
            .map(|e| e.2)
            .ok_or_else(|| bad(format!("container keybag has no tag-{tag} entry for this volume")))
    };
    let vek_blob = wrapped_key(find(KB_TAG_VOLUME_KEY)?)?;
    let loc = slice(find(KB_TAG_VOLUME_UNLOCK_RECORDS)?, 0, 16)?;
    let vkb = read_keybag(c, u64le(loc, 0), u64le(loc, 8), vol_uuid, OBJECT_TYPE_VOLUME_KEYBAG)?;

    // Each unlock record wraps the KEK for one user (or the recovery key); try them all.
    for (_, tag, data) in keybag_entries(&vkb)? {
        if tag != KB_TAG_VOLUME_UNLOCK_RECORDS {
            continue;
        }
        let kek_blob = wrapped_key(data)?;
        let (Some(iters), Some(salt)) = (kek_blob.iterations, kek_blob.salt) else { continue };
        let derived = pbkdf2_sha256(password.as_bytes(), salt, iters);
        let Ok(kek) = unwrap(&derived[..kek_blob.key_len()], kek_blob.wrapped) else { continue };
        let vek = unwrap(&kek, vek_blob.wrapped)?;
        return xts_for_vek(&vek, vek_blob.uuid);
    }
    Err(io::Error::new(io::ErrorKind::PermissionDenied, "wrong password"))
}

/// A 256-bit VEK is the XTS key pair. A 128-bit one (volumes converted from CoreStorage) gets its tweak key
/// from SHA-256(VEK || the UUID in the VEK blob), as verified on a converted image.
fn xts_for_vek(vek: &[u8], blob_uuid: &[u8]) -> io::Result<Xts> {
    match vek.len() {
        32 => Xts::new(vek),
        16 => Xts::new(&[vek, &Sha256::new().chain_update(vek).chain_update(blob_uuid).finalize()[..16]].concat()),
        n => Err(bad(format!("unexpected {n}-byte volume key"))),
    }
}

/// Reads and decrypts a keybag; keybags are AES-XTS encrypted with their owner's UUID as both keys.
fn read_keybag(c: &Container, paddr: u64, blocks: u64, uuid: &[u8], want_type: u32) -> io::Result<Vec<u8>> {
    if paddr == 0 || blocks == 0 {
        return Err(bad("no keybag (volume encrypted without a software keybag?)"));
    }
    let mut b = c.read_block(paddr)?;
    // shortcut: only the first block is read; keybags with many unlock records can span more.
    Xts::new(&[uuid, uuid].concat())?.decrypt(&mut b, paddr * c.block_size / 512);
    if !checksum_ok(&b) || u32le(&b, 24) != want_type {
        return Err(bad(format!("keybag at block {paddr} didn't decrypt (bad checksum or type)")));
    }
    Ok(b)
}

/// Keybag entries (uuid, tag, data) from a decrypted media_keybag_t block.
fn keybag_entries(block: &[u8]) -> io::Result<Vec<KeybagEntry<'_>>> {
    let nkeys = u16le(slice(block, 32, 16)?, 2) as usize;
    let mut off = 48;
    let mut out = vec![];
    for _ in 0..nkeys {
        let h = slice(block, off, 24)?;
        let len = u16le(h, 18) as usize;
        out.push((h[..16].try_into().unwrap(), u16le(h, 16), slice(block, off + 24, len)?));
        off += (24 + len).div_ceil(16) * 16;
    }
    Ok(out)
}

/// The useful fields of a wrapped KEK/VEK blob: SEQUENCE { [0] version, [1] hmac, [2] salt,
/// [3] { [0] version, [1] uuid, [2] flags, [3] wrapped key, [4] iterations, [5] salt } }.
struct WrappedKey<'a> {
    uuid: &'a [u8],
    flags: &'a [u8],
    wrapped: &'a [u8],
    iterations: Option<u32>,
    salt: Option<&'a [u8]>,
}

impl WrappedKey<'_> {
    /// Flag 0x2 marks a 128-bit key (CoreStorage conversions); otherwise 256-bit.
    fn key_len(&self) -> usize {
        if self.flags.first().is_some_and(|f| f & 0x2 != 0) { 16 } else { 32 }
    }
}

fn wrapped_key(blob: &[u8]) -> io::Result<WrappedKey<'_>> {
    let outer = der(blob)?;
    let (0x30, seq) = *outer.first().ok_or_else(|| bad("empty key blob"))? else {
        return Err(bad("key blob is not a DER sequence"));
    };
    let fields = der(seq)?;
    let inner = der(fields.iter().find(|f| f.0 == 0xa3).ok_or_else(|| bad("key blob has no [3]"))?.1)?;
    let get = |t: u8| inner.iter().find(|f| f.0 == t).map(|f| f.1);
    let flags = get(0x82).unwrap_or(&[]);
    let wrapped = get(0x83).ok_or_else(|| bad("key blob has no wrapped key"))?;
    let mut k = WrappedKey {
        uuid: get(0x81).unwrap_or(&[]),
        flags,
        wrapped,
        iterations: get(0x84).map(|b| b.iter().fold(0u32, |a, &x| a << 8 | x as u32)),
        salt: get(0x85),
    };
    // The field is always 40 bytes; a 128-bit key's wrapping is 24 bytes followed by zero padding.
    k.wrapped = slice(k.wrapped, 0, k.key_len() + 8)?;
    Ok(k)
}

/// RFC 3394 AES key unwrap with a 128- or 256-bit key-encryption key.
fn unwrap(kek: &[u8], wrapped: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = vec![0; wrapped.len().saturating_sub(8)];
    let ok = match kek.len() {
        16 => aes_kw::KwAes128::new_from_slice(kek).unwrap().unwrap_key(wrapped, &mut out).is_ok(),
        32 => aes_kw::KwAes256::new_from_slice(kek).unwrap().unwrap_key(wrapped, &mut out).is_ok(),
        n => return Err(bad(format!("bad key-wrapping key length {n}"))),
    };
    if !ok {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "key unwrap failed (wrong password?)"));
    }
    Ok(out)
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password, salt, rounds)
}

/// Minimal DER reader: returns (tag, contents) pairs at one nesting level.
fn der(mut b: &[u8]) -> io::Result<Vec<(u8, &[u8])>> {
    let mut out = vec![];
    while !b.is_empty() {
        let tag = b[0];
        let (len, hdr) = match slice(b, 1, 1)?[0] {
            n if n < 0x80 => (n as usize, 2),
            0x81 => (slice(b, 2, 1)?[0] as usize, 3),
            0x82 => (u16::from_be_bytes(slice(b, 2, 2)?.try_into().unwrap()) as usize, 4),
            n => return Err(bad(format!("unsupported DER length byte {n:#x}"))),
        };
        out.push((tag, slice(b, hdr, len)?));
        b = &b[hdr + len..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn rfc3394_vector() {
        // RFC 3394 section 4.1: 128-bit key data wrapped with a 128-bit KEK.
        let kek: Vec<u8> = (0..16).collect();
        let wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        assert_eq!(unwrap(&kek, &wrapped).unwrap(), hex("00112233445566778899AABBCCDDEEFF"));
        assert_eq!(unwrap(&[1; 16], &wrapped).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn der_lengths() {
        let mut long = vec![0x04, 0x81, 200];
        long.extend([7; 200]);
        long.extend([0x80, 0x01, 0x05]);
        let items = der(&long).unwrap();
        assert_eq!((items[0].0, items[0].1.len()), (0x04, 200));
        assert_eq!(items[1], (0x80, &[5u8][..]));
        assert!(der(&[0x04, 0x05, 1]).is_err(), "truncated content must error, not panic");
    }
}
