"""Explicit local Docker smoke of the pinned Graph bridge and Interset sources.

The image is supplied by immutable sha256 identity and must be a local,
unqualified worker candidate. No pull, network access, or host mounts occur.
This is not a native-platform or release acceptance test.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import uuid


def run(image: str, platform: str, arguments: list[str], payload: bytes = b"") -> subprocess.CompletedProcess:
    name = "ud-agent-perl-smoke-" + uuid.uuid4().hex
    command = ["docker", "run", "--rm", "-i", "--pull=never", "--platform", platform,
               "--name", name, "--network", "none", "--read-only", "--user", "10001:10001",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "512m",
               "--pids-limit", "128", "--entrypoint", "perl", image, *arguments]
    try:
        return subprocess.run(command, input=payload, capture_output=True, timeout=90, check=False)
    finally:
        inspect = subprocess.run(["docker", "container", "inspect", name], capture_output=True, timeout=15, check=False)
        if inspect.returncode == 0:
            removed = subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=30, check=False)
            if removed.returncode:
                raise RuntimeError("could not remove owned Perl smoke container")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="local immutable image identity, sha256:<hex>")
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--context-sha256", required=True, help="SHA-256 of the exact build input manifest")
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image) or not re.fullmatch(r"[0-9a-f]{64}", args.context_sha256):
        raise ValueError("immutable image and build-manifest hashes are required")
    info = subprocess.run(["docker", "image", "inspect", args.image], capture_output=True, text=True, timeout=30, check=True)
    images = json.loads(info.stdout)
    if len(images) != 1 or images[0]["Id"] != args.image or images[0]["Architecture"] != args.arch or images[0]["Config"]["User"] != "10001:10001" or images[0]["Config"]["Labels"].get("org.ud-agent.release-qualified") != "false":
        raise ValueError("worker image identity, architecture, user, or qualification does not match")
    arch = "linux/" + args.arch
    bridge = ["/opt/ud-agent/worker/ud_agent/perl/graph_bridge.pl"]
    request = {"operation": "inspect_enhanced", "nodes": ["2", "1"], "edges": [
        {"head": "1", "dependent": "2", "relation": "nsubj"}, {"head": "0", "dependent": "1", "relation": "root"}]}
    result = run(args.image, arch, bridge, json.dumps(request).encode())
    expected = {"ok": True, "nodes": [
        {"id": "0", "in_degree": 0, "out_degree": 1, "incoming": []},
        {"id": "1", "in_degree": 1, "out_degree": 1, "incoming": [{"head": "0", "relation": "root"}]},
        {"id": "2", "in_degree": 1, "out_degree": 0, "incoming": [{"head": "1", "relation": "nsubj"}]}]}
    if result.returncode or result.stderr or json.loads(result.stdout) != expected:
        raise RuntimeError("real pinned Graph/Node bridge result differs from the expected graph")
    request["edges"].append(request["edges"][0])
    duplicate = run(args.image, arch, bridge, json.dumps(request).encode())
    if duplicate.returncode != 1 or duplicate.stderr or json.loads(duplicate.stdout) != {"ok": False, "error": "duplicate_edge"}:
        raise RuntimeError("duplicate graph edge was not rejected")
    conversion = run(args.image, arch, ["-MLingua::Interset=decode,encode", "-e",
        'my $f=decode("en::penn","NNS"); print encode("mul::uposf",$f),"\\n";'])
    if conversion.returncode or conversion.stderr or conversion.stdout != b"NOUN\tNumber=Plur\n":
        raise RuntimeError("pinned Interset tagset conversion differs from the expected result")
    host = subprocess.run(["docker", "info", "--format", "{{.Architecture}}"], capture_output=True, text=True, timeout=30, check=True).stdout.strip()
    native = (host in ("aarch64", "arm64") and args.arch == "arm64") or (host in ("x86_64", "amd64") and args.arch == "amd64")
    print(json.dumps({"status": "unqualified_smoke_passed", "image_id": args.image,
                      "architecture": arch, "docker_server_architecture": host, "native": native,
                      "build_manifest_sha256": args.context_sha256, "network": "none", "read_only": True,
                      "uid_gid": "10001:10001", "graph_bridge": "passed", "interset_conversion": "passed",
                      "limitations": ["Not full OCI/runtime acceptance", "Native execution depends on Docker host architecture"]}, sort_keys=True))


if __name__ == "__main__":
    main()
