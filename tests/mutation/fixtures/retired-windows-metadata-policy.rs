//! Bounds validation runs before passing serialized recovery data to Win32.
use std::io;
pub const MAX_METADATA: usize = 256 * 1024;
fn bad() -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, "invalid Windows recovery metadata") }
fn u16_at(bytes: &[u8], offset: usize) -> io::Result<usize> { Ok(u16::from_le_bytes(bytes.get(offset..offset + 2).ok_or_else(bad)?.try_into().map_err(|_| bad())?) as usize) }
fn u32_at(bytes: &[u8], offset: usize) -> io::Result<usize> { Ok(u32::from_le_bytes(bytes.get(offset..offset + 4).ok_or_else(bad)?.try_into().map_err(|_| bad())?) as usize) }

pub fn validate_security(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() < 20 || bytes.len() > MAX_METADATA || bytes[0] != 1 || u16_at(bytes, 2)? & 0x8000 == 0 { return Err(bad()); }
    let mut ranges = Vec::new();
    for field in [4, 8, 12, 16] {
        let offset = u32_at(bytes, field)?;
        if offset == 0 { continue; }
        if offset < 20 || offset % 4 != 0 { return Err(bad()); }
        let size = if field < 12 {
            let head = bytes.get(offset..offset + 8).ok_or_else(bad)?;
            if head[0] != 1 || head[1] > 15 { return Err(bad()); }
            8 + 4 * head[1] as usize
        } else {
            let head = bytes.get(offset..offset + 8).ok_or_else(bad)?;
            if ![2, 4].contains(&head[0]) { return Err(bad()); }
            let size = u16_at(bytes, offset + 2)?;
            if size < 8 || offset + size > bytes.len() { return Err(bad()); }
            let mut next = offset + 8;
            for _ in 0..u16_at(bytes, offset + 4)? {
                let ace = bytes.get(next..next + 4).ok_or_else(bad)?;
                let length = u16_at(bytes, next + 2)?;
                if length < 4 || next + length > offset + size || ![0, 1, 2, 17].contains(&ace[0]) { return Err(bad()); }
                if length < 16 { return Err(bad()); }
                let sid = bytes.get(next + 8..next + 16).ok_or_else(bad)?;
                if sid[0] != 1 || sid[1] > 15 || 16 + 4 * (sid[1] as usize) > length { return Err(bad()); }
                next += length;
            }
            size
        };
        if offset + size > bytes.len() { return Err(bad()); }
        for &(start, end) in &ranges {
            if offset < end && start < offset + size && (start, end) != (offset, offset + size) { return Err(bad()); }
        }
        ranges.push((offset, offset + size));
    }
    Ok(())
}

pub fn validate_backup(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_METADATA { return Err(bad()); }
    let mut position = 0;
    while position < bytes.len() {
        let header = bytes.get(position..position + 20).ok_or_else(bad)?;
        let id = u32_at(header, 0)?;
        let size = u64::from_le_bytes(header[8..16].try_into().map_err(|_| bad())?);
        let name_size = u32_at(header, 16)?;
        if ![2, 4, 6].contains(&id) || size > MAX_METADATA as u64 || name_size % 2 != 0 || name_size > 65534 { return Err(bad()); }
        let name = bytes.get(position + 20..position + 20 + name_size).ok_or_else(bad)?;
        if id == 4 {
            let wide: Vec<u16> = name.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
            let name = String::from_utf16(&wide).map_err(|_| bad())?;
            let stream = name.strip_prefix(':').and_then(|value| value.strip_suffix(":$DATA")).ok_or_else(bad)?;
            if stream.is_empty() || stream.contains([':', '/', '\\', '\0']) { return Err(bad()); }
        } else if name_size != 0 { return Err(bad()); }
        let payload = 20usize.checked_add(name_size).and_then(|length| length.checked_add(usize::try_from(size).ok()?)).ok_or_else(bad)?;
        position = position.checked_add(payload).ok_or_else(bad)?;
        if position > bytes.len() { return Err(bad()); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_metadata_keeps_the_structured_invalid_input_diagnostic() {
        let error = validate_security(&[]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "invalid Windows recovery metadata");
    }
    #[test]
    fn bounds_security_offsets_and_ace_sids() {
        let mut descriptor = vec![0u8; 20]; descriptor[0] = 1; descriptor[3] = 0x80;
        assert!(validate_security(&descriptor).is_ok());
        descriptor[4..8].copy_from_slice(&400u32.to_le_bytes());
        assert!(validate_security(&descriptor).is_err());
        descriptor[4..8].fill(0); descriptor[16..20].copy_from_slice(&20u32.to_le_bytes());
        descriptor.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
        assert!(validate_security(&descriptor).is_ok());
        descriptor[24] = 1;
        assert!(validate_security(&descriptor).is_err());
    }
    #[test]
    fn rejects_external_backup_links_and_truncated_streams() {
        let name: Vec<u8> = ":note:$DATA".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut bytes = Vec::new(); bytes.extend_from_slice(&4u32.to_le_bytes()); bytes.extend_from_slice(&0u32.to_le_bytes()); bytes.extend_from_slice(&1u64.to_le_bytes()); bytes.extend_from_slice(&(name.len() as u32).to_le_bytes()); bytes.extend_from_slice(&name); bytes.push(b'x');
        assert!(validate_backup(&bytes).is_ok());
        assert!(validate_backup(&bytes[..bytes.len() - 1]).is_err());
        bytes[0] = 5; assert!(validate_backup(&bytes).is_err());
    }
    // Byte recipes follow MS-DTYP SECURITY_DESCRIPTOR/SID/ACL and WIN32_STREAM_ID;
    // these checks exercise serialized inputs without needing a Windows host.
    fn sid(count: u8) -> Vec<u8> {
        let mut bytes = vec![1, count, 0, 0, 0, 0, 0, 5];
        for value in 0..count { bytes.extend_from_slice(&(1000 + u32::from(value)).to_le_bytes()); }
        bytes
    }
    fn descriptor(field: usize, object: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 20]; bytes[0] = 1; bytes[3] = 0x80;
        bytes[field..field + 4].copy_from_slice(&20u32.to_le_bytes());
        bytes.extend_from_slice(object); bytes
    }
    fn ace(kind: u8, count: u8) -> Vec<u8> {
        let identity = sid(count);
        let mut bytes = vec![kind, 0]; bytes.extend_from_slice(&((8 + identity.len()) as u16).to_le_bytes());
        bytes.extend_from_slice(&0x0012_0089u32.to_le_bytes()); bytes.extend_from_slice(&identity); bytes
    }
    fn acl(entries: &[Vec<u8>]) -> Vec<u8> {
        let size = 8 + entries.iter().map(Vec::len).sum::<usize>();
        let mut bytes = vec![2, 0]; bytes.extend_from_slice(&(size as u16).to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes()); bytes.extend_from_slice(&[0, 0]);
        for item in entries { bytes.extend_from_slice(item); } bytes
    }
    fn stream(id: u32, name: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new(); bytes.extend_from_slice(&id.to_le_bytes()); bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes()); bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bytes.extend_from_slice(name); bytes.extend_from_slice(payload); bytes
    }
    #[test]
    fn admits_exact_security_bounds_and_separate_shared_and_adjacent_objects() {
        assert_eq!(MAX_METADATA, 262144);
        let header = descriptor(4, &sid(0));
        assert!(validate_security(&header).is_ok());
        let mut maximum = header.clone(); maximum.resize(262144, 0);
        assert!(validate_security(&maximum).is_ok()); maximum.push(0);
        assert!(validate_security(&maximum).is_err());
        for field in [4, 8] {
            for count in [0, 1, 2, 15] { assert_eq!(validate_security(&descriptor(field, &sid(count))).is_ok(), true, "SID {field}/{count}"); }
        }
        for field in [12, 16] {
            for kind in [0, 1, 2, 17] {
                assert_eq!(validate_security(&descriptor(field, &acl(&[ace(kind, 0), ace(kind, 2)]))).is_ok(), true, "ACE {field}/{kind}");
            }
            let mut revision4 = acl(&[ace(0, 15)]); revision4[0] = 4;
            assert!(validate_security(&descriptor(field, &revision4)).is_ok());
        }
        let mut shared = descriptor(4, &sid(2)); shared[8..12].copy_from_slice(&20u32.to_le_bytes());
        assert!(validate_security(&shared).is_ok());
        let mut adjacent = descriptor(4, &sid(2)); adjacent[8..12].copy_from_slice(&36u32.to_le_bytes()); adjacent.extend(sid(1));
        assert!(validate_security(&adjacent).is_ok());
        // Reverse field order is valid: target order is not constrained by the header.
        adjacent[4..8].copy_from_slice(&36u32.to_le_bytes()); adjacent[8..12].copy_from_slice(&20u32.to_le_bytes());
        assert!(validate_security(&adjacent).is_ok());
        let mut overlapping = descriptor(4, &sid(3));
        overlapping[8..12].copy_from_slice(&24u32.to_le_bytes());
        overlapping[24..32].copy_from_slice(&sid(0));
        assert!(validate_security(&overlapping).is_err());
    }
    #[test]
    fn rejects_malformed_security_headers_offsets_sids_acls_and_aces() {
        let valid = descriptor(16, &acl(&[ace(0, 2), ace(1, 1)]));
        for length in 0..20 { assert_eq!(validate_security(&valid[..length]).is_err(), true, "header {length}"); }
        for (offset, byte) in [(0, 0), (0, 2), (3, 0)] {
            let mut bad = valid.clone(); bad[offset] = byte; assert!(validate_security(&bad).is_err());
        }
        let mut shifted = descriptor(4, &sid(1)); shifted.insert(20, 0); shifted[4..8].copy_from_slice(&21u32.to_le_bytes());
        assert!(validate_security(&shifted).is_err());
        let mut padded_acl = descriptor(16, &acl(&[])); padded_acl.extend_from_slice(&[0; 8]);
        assert!(validate_security(&padded_acl).is_ok());
        let mut short_empty = acl(&[]); short_empty[2..4].copy_from_slice(&7u16.to_le_bytes());
        assert!(validate_security(&descriptor(16, &short_empty)).is_err());
        let mut underdeclared = acl(&[ace(0, 2)]); underdeclared[2..4].copy_from_slice(&8u16.to_le_bytes());
        assert!(validate_security(&descriptor(16, &underdeclared)).is_err());
        for field in [4, 8, 12, 16] {
            for offset in [1u32, 16, 19, 21, 0xffff_fffc] {
                let mut bad = valid.clone(); bad[field..field + 4].copy_from_slice(&offset.to_le_bytes());
                assert_eq!(validate_security(&bad).is_err(), true, "offset {field}/{offset}");
            }
        }
        for field in [4, 8] {
            for (index, value) in [(0, 0), (0, 2), (1, 16)] {
                let mut object = sid(2); object[index] = value;
                assert!(validate_security(&descriptor(field, &object)).is_err());
            }
            let mut truncated = descriptor(field, &sid(2)); truncated.pop();
            assert!(validate_security(&truncated).is_err());
        }
        for field in [12, 16] {
            for (index, value) in [(0, 0), (0, 3), (2, 7), (2, 255), (4, 3), (8, 3), (10, 3), (10, 15), (10, 255), (16, 0), (16, 2), (17, 16), (17, 15)] {
                let mut object = acl(&[ace(0, 2), ace(1, 1)]); object[index] = value;
                assert_eq!(validate_security(&descriptor(field, &object)).is_err(), true, "ACL {field}/{index}/{value}");
            }
            let object = acl(&[ace(0, 2)]);
            for length in 0..object.len() { assert_eq!(validate_security(&descriptor(field, &object[..length])).is_err(), true, "truncation {field}/{length}"); }
        }
    }
    #[test]
    fn bounds_and_confines_backup_streams_with_exact_multistream_offsets() {
        assert!(validate_backup(&[]).is_ok());
        for id in [2, 6] {
            let bytes = stream(id, &[], b"abc"); assert!(validate_backup(&bytes).is_ok());
            for length in 1..bytes.len() { assert!(validate_backup(&bytes[..length]).is_err()); }
            assert!(validate_backup(&stream(id, &[0, 0], b"abc")).is_err());
        }
        let name: Vec<u8> = ":note:$DATA".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut combined = stream(2, &[], b"security"); combined.extend(stream(4, &name, b"note")); combined.extend(stream(6, &[], b"other"));
        assert!(validate_backup(&combined).is_ok());
        let exact = stream(2, &[], &vec![0; 262124]); assert_eq!(exact.len(), 262144);
        assert!(validate_backup(&exact).is_ok());
        let mut oversized = exact; oversized.push(0); assert!(validate_backup(&oversized).is_err());
        for id in [0, 1, 3, 5, 7, u32::MAX] { assert!(validate_backup(&stream(id, &[], &[])).is_err()); }
        for text in ["", ":$DATA", "::$DATA", "note:$DATA", ":note:OTHER", ":a/b:$DATA", ":a\\b:$DATA", ":a:b:$DATA", ":a\0b:$DATA"] {
            let name: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            assert_eq!(validate_backup(&stream(4, &name, b"x")).is_err(), true, "stream {text:?}");
        }
        assert!(validate_backup(&stream(4, &[0, 0xd8], b"x")).is_err());
        let mut odd = stream(4, &name, b"x"); odd[16..20].copy_from_slice(&1u32.to_le_bytes()); assert!(validate_backup(&odd).is_err());
        let mut large = stream(2, &[], &[]); large[8..16].copy_from_slice(&262145u64.to_le_bytes()); assert!(validate_backup(&large).is_err());
        for size in [u64::MAX - 19, u64::MAX] {
            let mut oversized = stream(2, &[], &[]); oversized[8..16].copy_from_slice(&size.to_le_bytes());
            assert_eq!(validate_backup(&oversized).is_err(), true, "oversized stream {size}");
        }
        let mut large_name = stream(2, &[], &[]); large_name[16..20].copy_from_slice(&65536u32.to_le_bytes()); assert!(validate_backup(&large_name).is_err());
        // The maximum UTF-16 name length is legal when the complete stream fits.
        let long_name = format!(":{}:$DATA", "n".repeat(32760));
        let wide: Vec<u8> = long_name.encode_utf16().flat_map(u16::to_le_bytes).collect(); assert_eq!(wide.len(), 65534);
        assert!(validate_backup(&stream(4, &wide, &[])).is_ok());
        let too_long = format!(":{}:$DATA", "n".repeat(32761));
        let bytes: Vec<u8> = too_long.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(validate_backup(&stream(4, &bytes, &[])).is_err());
        let mut odd_named: Vec<u8> = ":note:$DATA".encode_utf16().flat_map(u16::to_le_bytes).collect(); odd_named.push(b'x');
        assert!(validate_backup(&stream(4, &odd_named, &[])).is_err());
    }

}
