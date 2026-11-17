//! Exercise the actual same-variant command, including its bounded wire input.
use std::io::Write;
use std::process::{Command, Output, Stdio};
fn json(bytes:&[u8])->serde_json::Value {
    let parsed=serde_json::from_slice(bytes);
    assert!(parsed.is_ok(),"successful parser must return complete JSON: {parsed:?}");
    parsed.unwrap()
}

fn invoke(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ud-rust-assertion-parser"))
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("original parser fixture starts");
    let written = child
        .stdin
        .take()
        .expect("fixture owns child stdin")
        .write_all(input);
    let output = child
        .wait_with_output()
        .expect("parser reaches a terminal status");
    assert!(
        written.is_ok() || !output.status.success(),
        "successful parser must consume its complete input"
    );
    output
}

#[test]
fn exact_cli_schema_contains_real_ast_sites_names_and_external_modules() {
    let output = invoke(&["--source"], b"// assert!(false);\nmod nested { #[test] fn real(){ assert_eq!(1,2); } }\nmod external;\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let value=json(&output.stdout);
    assert_eq!(
        value,
        serde_json::json!({"schema_version":1,"sites":[{"line":2,"column":33,"macro":"assert_eq"}],"tests":["nested::real"],"external_modules":[{"modules":["external"],"path":null,"test_only":false}]})
    );
    assert_eq!(output.stdout.last(), Some(&b'\n'));
}

#[test]
fn integration_switch_authorizes_helpers_without_inventing_test_names() {
    let source = b"fn helper(){assert_ne!(1,2);}";
    let ordinary = invoke(&["--source"], source);
    let integration = invoke(&["--source", "--test-scope"], source);
    assert!(ordinary.status.success() && integration.status.success());
    let ordinary=json(&ordinary.stdout);
    let integration=json(&integration.stdout);
    assert_eq!(ordinary["sites"], serde_json::json!([]));
    assert_eq!(
        integration["sites"],
        serde_json::json!([{"line":1,"column":13,"macro":"assert_ne"}])
    );
    assert_eq!(integration["tests"], serde_json::json!([]));
}

#[test]
fn malformed_arguments_source_and_non_utf8_never_emit_partial_json() {
    for (arguments, input) in [
        (vec![], b"".as_slice()),
        (vec!["--source", "extra"], b"fn main(){}".as_slice()),
        (vec!["--test-scope", "--source"], b"".as_slice()),
        (vec!["--source"], b"fn broken(".as_slice()),
        (vec!["--source"], b"\xff\xfe".as_slice()),
    ] {
        let output = invoke(&arguments, input);
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "rejected input must not emit an authorization inventory"
        );
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn empty_source_is_a_complete_empty_inventory_and_oversized_input_is_rejected() {
    let output = invoke(&["--source"], b"");
    assert!(output.status.success());
    let parsed=json(&output.stdout);
    assert_eq!(
        parsed,
        serde_json::json!({"schema_version":1,"sites":[],"tests":[],"external_modules":[]})
    );
    let output = invoke(&["--source"], &vec![b' '; 16 * 1024 * 1024 + 1]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Rust source exceeds parser bound"));
}

#[test]
fn cfg_mode_preserves_platform_ancestry_and_rejects_unknown_predicate_grammar() {
    let output=invoke(&["--cfg-regions"],b"#[cfg(windows)] mod platform;\n#[cfg(target_os=\"linux\")] fn linux(){}\nfn common(){if cfg!(windows){windows();}else{unix();}}\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed=json(&output.stdout);
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(
        parsed["external_modules"][0]["modules"],
        serde_json::json!(["platform"])
    );
    assert!(
        parsed["external_modules"][0]["predicate"]
            .to_string()
            .contains("windows")
    );
    assert!(parsed["regions"].is_array(), "cfg regions must be an array");
    assert_eq!(parsed["regions"].as_array().unwrap().len(), 4);
    for source in [
        "#[cfg(not(unix,windows))]fn f(){}",
        "#[cfg]fn f(){}",
        "#[cfg_attr]fn f(){}",
        "#[cfg(target_os=1)]fn f(){}",
    ] {
        let rejected = invoke(&["--cfg-regions"], source.as_bytes());
        assert!(!rejected.status.success());
        assert!(rejected.stdout.is_empty());
    }
}
