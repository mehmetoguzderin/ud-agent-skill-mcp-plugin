//! Portable validation for the scoped Windows same-object transaction backend.
use std::io;
// Recovery metadata passes through JavaScript journals. NTFS volume IDs can
// exceed Number.MAX_SAFE_INTEGER, so new receipts retain their decimal bytes.
pub mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Value { Decimal(String), Legacy(u64) }
        match Value::deserialize(deserializer)? {
            Value::Legacy(value) => Ok(value),
            Value::Decimal(value) => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || value.len() > 1 && value.starts_with('0') {
                    return Err(serde::de::Error::custom("invalid decimal volume ID"));
                }
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    }
}
pub const FILE_SUPPORTS_TRANSACTIONS: u32 = 0x0020_0000;
pub fn supports_ntfs(filesystem: &str, flags: u32) -> bool { filesystem == "NTFS" && flags & FILE_SUPPORTS_TRANSACTIONS != 0 }
fn hash(value: &str) -> bool { value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) }
fn relative(value: &str) -> bool { !value.is_empty() && !value.contains(['\\', ':', '\0']) && value.split('/').all(|part| !part.is_empty() && part != "." && part != "..") }
pub fn validate_preserved(source: &str, backup: &str, before: &str) -> io::Result<()> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, "invalid preserved-file recovery authority");
    if !relative(source) || !relative(backup) || !hash(before) { return Err(bad()); }
    let (source_parent, _) = source.rsplit_once('/').unwrap_or(("", source));
    let (backup_parent, backup_name) = backup.rsplit_once('/').unwrap_or(("", backup));
    if source_parent != backup_parent || !backup_name.strip_prefix(".ud-agent-original-").is_some_and(hash) { return Err(bad()); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_volume_ids_survive_javascript_json_round_trips() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Receipt { #[serde(with = "decimal_u64")] volume: u64 }
        for volume in [0, 9_007_199_254_740_993, u64::MAX] {
            let original = Receipt { volume };
            let json = serde_json::to_value(&original).unwrap();
            assert_eq!(json["volume"].as_str(), Some(volume.to_string().as_str()));
            let relayed = serde_json::to_string(&json).unwrap();
            assert_eq!(serde_json::from_str::<Receipt>(&relayed).unwrap(), original);
        }
        assert_eq!(serde_json::from_str::<Receipt>(r#"{"volume":42}"#).unwrap().volume, 42);
        for value in [r#"{"volume":"01"}"#, r#"{"volume":"-1"}"#, r#"{"volume":"18446744073709551616"}"#] {
            assert!(serde_json::from_str::<Receipt>(value).is_err());
        }
    }
    #[test]
    fn ordinary_user_backend_requires_the_actual_local_ntfs_transaction_capability() {
        assert!(supports_ntfs("NTFS", 0x0020_0000)); assert!(supports_ntfs("NTFS", 0x0020_0000 | 0x100));
        for (filesystem, flags) in [("NTFS", 0), ("ReFS", 0x0020_0000), ("FAT32", 0x0020_0000), ("ntfs", 0x0020_0000), ("", 0x0020_0000), ("NTFS", 0x100)] { assert!(!supports_ntfs(filesystem, flags)); }
    }
    #[test]
    fn opaque_recovery_is_bound_to_exact_source_hash_and_same_confined_parent() {
        let digest = "a".repeat(64); let backup = format!("sub dir/.ud-agent-original-{digest}");
        validate_preserved("sub dir/é.conllu", &backup, &digest).unwrap();
        validate_preserved("file", &format!(".ud-agent-original-{digest}"), &digest).unwrap();
        for source in ["", ".", "..", "/file", "a//file", "a/../file", "C:/file", "a\\file", "a\0file"] { assert!(validate_preserved(source, &backup, &digest).is_err(), "{source:?}"); }
        for target in ["../escape", "/escape", "sub dir/.ud-agent-original-short", "other/.ud-agent-original-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sub dir/.ud-agent-original-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] { assert!(validate_preserved("sub dir/file", target, &digest).is_err(), "{target:?}"); }
        for hash in ["", "abc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] { assert!(validate_preserved("sub dir/file", &backup, hash).is_err()); }
    }
}
