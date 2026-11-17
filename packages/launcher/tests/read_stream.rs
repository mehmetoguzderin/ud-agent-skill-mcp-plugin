use sha2::{Digest,Sha256};
use std::fs::{self,File};
use std::io::{Read,Seek,SeekFrom,Write};
use std::path::{Path,PathBuf};
use std::process::{Command,Stdio};
use std::time::{SystemTime,UNIX_EPOCH};

fn root()->PathBuf { let name=format!("ud-guard-stream-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());let root=std::env::temp_dir().join(name);fs::create_dir(&root).unwrap();fs::canonicalize(root).unwrap() }
fn command(root:&Path,path:&str,limit:u64)->Command {
    let output=Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")).args(["identity","--root"]).arg(root).output().unwrap();assert!(output.status.success(),"identity fixture rejected: {:?}",output.stderr);
    let value:serde_json::Value=serde_json::from_slice(&output.stdout).unwrap();let mut cmd=Command::new(env!("CARGO_BIN_EXE_ud-agent-guard"));cmd.arg("read-stream").arg("--root").arg(root).args(["--path",path,"--max-bytes",&limit.to_string(),"--root-device",value["device"].as_str().unwrap(),"--root-inode",value["inode"].as_str().unwrap()]);cmd
}

#[test]
fn streams_more_than_64_mib_exactly_without_a_buffered_read_limit() {
    let root=root();let length=70*1024*1024u64;let mut file=File::create(root.join("large.pack")).unwrap();file.set_len(length).unwrap();file.seek(SeekFrom::Start(64*1024*1024+3)).unwrap();file.write_all(&[85]).unwrap();file.seek(SeekFrom::Start(length-1)).unwrap();file.write_all(&[161]).unwrap();file.sync_all().unwrap();drop(file);
    let mut child=command(&root,"large.pack",length).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();let mut output=child.stdout.take().unwrap();let mut actual=Sha256::new();let mut count=0;let mut chunk=[0u8;65536];loop{let n=output.read(&mut chunk).unwrap();if n==0{break}actual.update(&chunk[..n]);count+=n as u64;}let result=child.wait_with_output().unwrap();assert!(result.status.success(),"stream rejected valid large file: {:?}",result.stderr);assert_eq!(count,length);
    let mut expected=Sha256::new();let mut position=0u64;while position<length{let n=std::cmp::min(65536,length-position)as usize;let mut bytes=vec![0u8;n];for (at,value) in [(64*1024*1024+3,85),(length-1,161)]{if at>=position&&at<position+n as u64{bytes[(at-position)as usize]=value;}}expected.update(bytes);position+=n as u64;}assert_eq!(actual.finalize().to_vec(),expected.finalize().to_vec());fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_missing_binding_limits_and_escape_before_emitting_data() {
    let root=root();fs::write(root.join("source"),b"123456").unwrap();
    for (path,limit) in [("source",0),("source",5),("source",20*1024*1024*1024+1),("../outside",1024)] {let result=command(&root,path,limit).output().unwrap();assert!(!result.status.success(),"invalid stream unexpectedly succeeded: {path} {limit}");assert!(result.stdout.is_empty(),"rejected stream emitted source bytes");}
    let unbound=Command::new(env!("CARGO_BIN_EXE_ud-agent-guard")).arg("read-stream").arg("--root").arg(&root).args(["--path","source","--max-bytes","10"]).output().unwrap();assert!(!unbound.status.success());assert!(unbound.stdout.is_empty());
    let result=command(&root,"source",6).output().unwrap();assert!(result.status.success(),"valid boundary stream failed");assert_eq!(result.stdout,b"123456");fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_same_bytes_path_replacement_while_retaining_the_original_fd() {
    let root=root();let file=File::create(root.join("source")).unwrap();file.set_len(8*1024*1024).unwrap();drop(file);
    let mut child=command(&root,"source",8*1024*1024).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();let mut output=child.stdout.take().unwrap();let mut first=[0];assert_eq!(output.read(&mut first).unwrap(),1);
    fs::rename(root.join("source"),root.join("old")).unwrap();let replacement=File::create(root.join("source")).unwrap();replacement.set_len(8*1024*1024).unwrap();drop(replacement);
    std::io::copy(&mut output,&mut std::io::sink()).unwrap();let result=child.wait_with_output().unwrap();assert!(!result.status.success(),"replacement identity was accepted");assert!(String::from_utf8_lossy(&result.stderr).contains("WORKTREE_CHANGED_DURING_SNAPSHOT"));fs::remove_dir_all(root).unwrap();
}
