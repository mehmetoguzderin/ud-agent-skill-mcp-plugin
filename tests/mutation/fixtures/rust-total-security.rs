
#[cfg(test)] mod boundary_proof {
 use super::*;
 #[test] fn hostile_empty_security_is_total() {
  let observed = std::panic::catch_unwind(|| validate_security(&[]));
  if observed.is_err() { eprintln!("{}", r#"{"schema_version":1,"event":"caught-boundary-panic","source_sha256":"cad86bd7dc42fdf85c6abb6e1a9bf945fdcf6314a014dce54f2ddfc298bf33a1","definition_sha256":"55df7c3525897903f9a6f8936cf38dd510014b7097bbe4790407e54d12325454","test":"boundary_proof::hostile_empty_security_is_total","boundary":"validate_security","input_hex":"","contract":"hostile bytes return InvalidInput without panic","expected":"Err(InvalidInput)","observed":"caught panic"}"#); }
  assert_eq!(observed.is_ok(), true, "public serialized-metadata boundary must never panic");
  assert_eq!(observed.unwrap().unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
 }
}
