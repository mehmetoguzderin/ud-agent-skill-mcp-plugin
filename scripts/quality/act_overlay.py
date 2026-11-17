#!/usr/bin/env python3
"""Generate an auditable local act overlay with an isolated canonical tool cache."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

import yaml


class WorkflowLoader(yaml.SafeLoader):
    """GitHub uses YAML 1.2: the key ``on`` must not become a boolean."""


WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, expression) for tag, expression in values if tag != "tag:yaml.org,2002:bool"]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$", re.I), list("tTfF"))


def _mapping(loader: WorkflowLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("workflow contains a duplicate mapping key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


WorkflowLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _local_sdk_steps(job: dict, job_id: str, architecture: str) -> list:
    if job_id != "native-arm" or architecture != "arm64":
        raise ValueError("local SDK staging is only permitted for native-arm on arm64")
    steps = job["steps"]
    matches = [index for index, step in enumerate(steps) if step.get("name") == "Receive the selected run's verified native ARM SDK"]
    if len(matches) != 1:
        raise ValueError("local SDK staging requires exactly one SDK download step")
    index = matches[0]
    step = steps[index]
    if (not re.fullmatch(r"actions/download-artifact@[a-f0-9]{40}", step.get("uses", ""))
            or step.get("if") != "matrix.target == 'linux-arm64'"
            or step.get("with", {}).get("path") != ".artifacts/mutation-ci-sdk"):
        raise ValueError("local SDK staging requires the pinned SDK download action")
    # Assign a new list: native and native-arm share a YAML steps alias.
    return steps[:index] + steps[index + 1:]


def generate(workflow: bytes, job_id: str, architecture: str, owner: str, image: str, additional_jobs: tuple[str, ...] = (), socket_gid: int | None = None, local_sdk: bool = False) -> tuple[dict, dict]:
    if architecture not in ("arm64", "amd64") or not re.fullmatch(r"[a-f0-9]{32}", owner):
        raise ValueError("invalid architecture or ownership token")
    if not re.fullmatch(r"ghcr\.io/catthehacker/ubuntu@sha256:[a-f0-9]{64}", image):
        raise ValueError("runner image must be pinned by digest")
    original = yaml.load(workflow.decode("utf-8"), Loader=WorkflowLoader)
    if not isinstance(original, dict) or not isinstance(original.get("jobs"), dict):
        raise ValueError("invalid workflow")
    job = original["jobs"].get(job_id)
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list) or not job["steps"]:
        raise ValueError("selected job must have nonempty steps")
    if "container" in job:
        raise ValueError("an existing job container requires an explicit reviewed overlay")
    selected = [job_id, *additional_jobs]
    if len(set(selected)) != len(selected) or any(not isinstance(original['jobs'].get(name), dict) or not original['jobs'][name].get('steps') or 'container' in original['jobs'][name] for name in selected):
        raise ValueError('additional overlay jobs must be distinct existing jobs without containers')
    if socket_gid is not None and (type(socket_gid) is not int or not 0 <= socket_gid <= 2**31 - 1):
        raise ValueError('invalid Docker socket group')
    overlay = copy.deepcopy(original)
    volume = f"ud-agent-act-{owner}-{architecture}"
    container = {
        "image": image,
        "options": f"--init --label io.github.mehmetoguzderin.ud-agent.act-owner={owner}" + (f" --group-add {socket_gid}" if socket_gid is not None else ""),
        "volumes": [
            "act-toolcache:/ud-agent-unused-shared-toolcache",
            f"{volume}:/opt/hostedtoolcache",
        ],
    }
    for name in selected: overlay["jobs"][name]["container"] = copy.deepcopy(container)
    if local_sdk:
        overlay["jobs"][job_id]["steps"] = _local_sdk_steps(overlay["jobs"][job_id], job_id, architecture)
    verify(original, overlay, job_id, volume, image, additional_jobs, socket_gid, local_sdk)
    receipt = {
        "schema_version": 1,
        "qualification": "local_actions_emulation_only",
        "workflow_sha256": hashlib.sha256(workflow).hexdigest(),
        "steps_sha256": hashlib.sha256(canonical(job["steps"])).hexdigest(),
        "owner": owner,
        "job": job_id,
        "overlay_jobs": selected,
        "docker_socket_gid": socket_gid,
        "architecture": architecture,
        "runner_image": image,
        "init_process": True,
        "toolcache_volume": volume,
        "canonical_toolcache": "/opt/hostedtoolcache",
        "shared_toolcache_accessed": False,
    }
    if local_sdk:
        receipt["sdk_transport"] = "verified-local-staging"
    return overlay, receipt


def verify(original: dict, overlay: dict, job_id: str, volume: str, image: str, additional_jobs: tuple[str, ...] = (), socket_gid: int | None = None, local_sdk: bool = False) -> None:
    expected = copy.deepcopy(original)
    container = {
        "image": image,
        "options": "--init --label io.github.mehmetoguzderin.ud-agent.act-owner=" + volume.removeprefix("ud-agent-act-").rsplit("-", 1)[0] + (f" --group-add {socket_gid}" if socket_gid is not None else ""),
        "volumes": ["act-toolcache:/ud-agent-unused-shared-toolcache", f"{volume}:/opt/hostedtoolcache"],
    }
    for name in (job_id, *additional_jobs): expected["jobs"][name]["container"] = copy.deepcopy(container)
    if local_sdk:
        expected["jobs"][job_id]["steps"] = _local_sdk_steps(expected["jobs"][job_id], job_id, volume.rsplit("-", 1)[-1])
    if overlay != expected:
        raise ValueError("overlay changes source workflow behavior beyond its declared local exceptions")
    if overlay["jobs"][job_id]["steps"] != expected["jobs"][job_id]["steps"]:
        raise ValueError("overlay changes test steps or action identities")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--job", default="native")
    parser.add_argument("--architecture", choices=("arm64", "amd64"), required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--dependency-job", action="append", default=[])
    parser.add_argument("--socket-gid", type=int)
    parser.add_argument("--local-sdk", action="store_true")
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("overlay output must be new")
    overlay, receipt = generate(args.workflow.read_bytes(), args.job, args.architecture, args.owner, args.image, tuple(args.dependency_job), args.socket_gid, args.local_sdk)
    # JSON is also valid YAML 1.2, avoiding serializer-dependent scalar changes.
    data = json.dumps(overlay, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as target:
        target.write(data)
    receipt["overlay_sha256"] = hashlib.sha256(data).hexdigest()
    receipt_path = args.output.with_suffix(args.output.suffix + ".receipt.json")
    with receipt_path.open("x", encoding="utf-8") as target:
        json.dump(receipt, target, indent=2)
        target.write("\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
