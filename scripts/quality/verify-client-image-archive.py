#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a selected private Docker/OCI save archive without extracting files."""
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile

DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
LABEL = "io.github.mehmetoguzderin.ud-agent.local-eval"


def require(value, message):
    if not value:
        raise ValueError(message)


def verify(archive, before):
    expected = before["Id"]
    require(DIGEST.fullmatch(expected) and before["Architecture"] == "arm64" and before["Os"] == "linux", "ARCHIVE_EXPECTED_IMAGE_INVALID")
    owner = before["Config"]["Labels"][LABEL]
    archive_hash = hashlib.sha256()
    with open(archive, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            archive_hash.update(chunk)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        require(0 < len(members) <= 50000, "ARCHIVE_MEMBER_COUNT_INVALID")
        named = {}
        for member in members:
            name = member.name.removeprefix("./")
            require(not name.startswith("/") and ".." not in name.split("/") and name not in named and (member.isfile() or member.isdir()), "ARCHIVE_MEMBER_INVALID")
            named[name] = member

        def metadata(name):
            member = named.get(name)
            require(member is not None and member.isfile() and member.size <= 16 * 1024 * 1024, "ARCHIVE_METADATA_INVALID")
            data = tar.extractfile(member).read()
            return data, json.loads(data)

        def blob(digest):
            require(isinstance(digest, str) and DIGEST.fullmatch(digest), "ARCHIVE_DIGEST_INVALID")
            data, document = metadata("blobs/sha256/" + digest[7:])
            require("sha256:" + hashlib.sha256(data).hexdigest() == digest, "ARCHIVE_BLOB_DIGEST_CHANGED")
            return document

        root_path = "blobs/sha256/" + expected[7:]
        if root_path in named:
            document = blob(expected)
            identity_kind = "oci-manifest"
            if "manifests" in document:
                identity_kind = "oci-index"
                matches = []
                for descriptor in document["manifests"]:
                    candidate = blob(descriptor["digest"])
                    if "config" not in candidate:
                        continue
                    config = blob(candidate["config"]["digest"])
                    if config.get("architecture") == "arm64" and config.get("os") == "linux":
                        matches.append((candidate, config))
                require(len(matches) == 1, "ARCHIVE_ARM64_MANIFEST_AMBIGUOUS")
                document, config = matches[0]
            else:
                config = blob(document["config"]["digest"])
            config_digest = document["config"]["digest"]
            layers = [{"path": "blobs/sha256/" + item["digest"][7:], "digest": item["digest"], "size": item["size"], "media": item.get("mediaType", "")} for item in document["layers"]]
            manifest_digest = expected
        else:
            manifest_data, manifests = metadata("manifest.json")
            require(isinstance(manifests, list) and len(manifests) == 1, "ARCHIVE_IMAGE_COUNT_INVALID")
            document = manifests[0]
            data, config = metadata(document["Config"])
            config_digest = "sha256:" + hashlib.sha256(data).hexdigest()
            require(config_digest == expected, "ARCHIVE_SELECTED_IMAGE_ABSENT")
            layers = [{"path": name, "digest": None, "size": named.get(name).size if named.get(name) else -1, "media": ""} for name in document["Layers"]]
            identity_kind, manifest_digest = "docker-config", "sha256:" + hashlib.sha256(manifest_data).hexdigest()
        require(config.get("architecture") == "arm64" and config.get("os") == "linux" and config.get("config", {}).get("Labels", {}).get(LABEL) == owner, "ARCHIVE_CONFIG_IDENTITY_CHANGED")
        diff_ids = config.get("rootfs", {}).get("diff_ids")
        require(diff_ids == before.get("RootFS", {}).get("Layers") and len(layers) == len(diff_ids) and len(layers) > 0, "ARCHIVE_ROOTFS_CHANGED")
        require(all(DIGEST.fullmatch(digest) for digest in diff_ids), "ARCHIVE_DIFF_ID_INVALID")
        total = 0
        verified_layers = []
        for index, layer in sorted(enumerate(layers), key=lambda row: named.get(row[1]["path"]).offset_data if named.get(row[1]["path"]) else -1):
            member = named.get(layer["path"])
            require(member is not None and member.isfile() and member.size == layer["size"], "ARCHIVE_LAYER_ABSENT_OR_CHANGED")
            raw = tar.extractfile(member)
            compressed_hash = hashlib.sha256()
            class Reader(io.RawIOBase):
                def readable(self): return True
                def read(self, size=-1):
                    value = raw.read(size)
                    compressed_hash.update(value)
                    return value
                def readinto(self, target):
                    value = self.read(len(target)); target[:len(value)] = value; return len(value)
            reader = Reader()
            media = layer["media"]
            if media.endswith("+gzip") or media == "application/vnd.docker.image.rootfs.diff.tar.gzip":
                payload = gzip.GzipFile(fileobj=reader)
            elif media.endswith("+zstd"):
                from compression import zstd
                payload = zstd.ZstdFile(reader)
            else:
                payload = reader
            uncompressed_hash = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: payload.read(1024 * 1024), b""):
                size += len(chunk); total += len(chunk)
                require(total <= max(before.get("Size", 0) * 2, 1024 * 1024) + 128 * 1024 * 1024, "ARCHIVE_LAYER_BUDGET_EXCEEDED")
                uncompressed_hash.update(chunk)
            for chunk in iter(lambda: reader.read(1024 * 1024), b""): pass
            require(layer["digest"] is None or "sha256:" + compressed_hash.hexdigest() == layer["digest"], "ARCHIVE_LAYER_BLOB_CHANGED")
            actual = "sha256:" + uncompressed_hash.hexdigest()
            require(actual == diff_ids[index], "ARCHIVE_LAYER_DIFF_ID_CHANGED")
            verified_layers.append({"index": index, "path": layer["path"], "diff_id": actual, "blob_digest": "sha256:" + compressed_hash.hexdigest(), "uncompressed_bytes": size})
        return {"kind": "verified-docker-or-oci-save", "archive_sha256": archive_hash.hexdigest(), "image_id": expected, "identity_kind": identity_kind, "identity_digest": expected, "manifest_digest": manifest_digest, "config_digest": config_digest, "architecture": "arm64", "os": "linux", "owner": owner, "diff_ids": diff_ids, "layers": sorted(verified_layers, key=lambda row: row["index"]), "layers_verified": True}


if __name__ == "__main__":
    require(len(sys.argv) == 3, "Usage: verify-client-image-archive.py ARCHIVE BEFORE_INSPECTION_JSON")
    with open(sys.argv[2], encoding="utf-8") as source:
        before = json.load(source)
    print(json.dumps(verify(sys.argv[1], before), separators=(",", ":")))
