#!/usr/bin/env python3
"""Fail-closed, resource-bounded verification of a release OCI archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast

MAX_ARCHIVE = 1_000_000_000
MAX_MEMBERS = 64
MAX_JSON = 16_000_000
MAX_COMPRESSED_LAYER = 500_000_000
MAX_UNCOMPRESSED_LAYER = 1_000_000_000
MAX_UNCOMPRESSED_TOTAL = 4_000_000_000
MAX_LAYER_MEMBERS = 200_000
MAX_TAR_NAME = 4_096
CHUNK = 1_048_576
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA = "application/vnd.oci.image.config.v1+json"
LAYER_MEDIA = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK):
            result.update(chunk)
    return "sha256:" + result.hexdigest()


def object_json(data: bytes, name: str) -> dict[str, Any]:
    if len(data) > MAX_JSON:
        fail(f"{name} exceeds JSON size limit")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid {name}: {error}")
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    return cast(dict[str, Any], value)


def exact_keys(value: dict[str, Any], required: set[str], optional: set[str], name: str) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing or unknown:
        fail(f"invalid {name} fields; missing={sorted(missing)}, unknown={sorted(unknown)}")


def descriptor(value: Any, media_types: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{name} descriptor must be an object")
    exact_keys(value, {"mediaType", "digest", "size"}, {"annotations", "platform"}, name)
    if value["mediaType"] not in media_types:
        fail(f"unsupported {name} media type")
    if not isinstance(value["digest"], str) or not DIGEST.fullmatch(value["digest"]):
        fail(f"invalid {name} digest")
    if not isinstance(value["size"], int) or isinstance(value["size"], bool) or value["size"] < 0:
        fail(f"invalid {name} size")
    for optional in ("annotations", "platform"):
        if optional in value and not isinstance(value[optional], dict):
            fail(f"invalid {name} {optional}")
    if "annotations" in value and not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value["annotations"].items()
    ):
        fail(f"invalid {name} annotations")
    return cast(dict[str, Any], value)


def load_archive(path: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    if not path.is_file() or path.stat().st_size > MAX_ARCHIVE:
        fail("OCI archive missing or exceeds size limit")
    members: dict[str, bytes] = {}
    allowed_dirs = {".", "blobs", "blobs/sha256"}
    try:
        with tarfile.open(path, "r:") as archive:
            entries = archive.getmembers()
            if len(entries) > MAX_MEMBERS:
                fail("OCI archive member count exceeds limit")
            for member in entries:
                pure = PurePosixPath(member.name)
                name = str(pure)
                if member.name.startswith("/") or ".." in pure.parts:
                    fail(f"unsafe OCI archive member: {member.name}")
                if member.isdir():
                    if name not in allowed_dirs:
                        fail(f"unexpected OCI archive directory: {member.name}")
                    continue
                if not member.isfile() or member.islnk() or member.issym() or member.linkname:
                    fail(f"unsupported OCI archive member: {member.name}")
                if name in members:
                    fail(f"duplicate OCI archive member: {member.name}")
                limit = MAX_JSON if name in {"oci-layout", "index.json"} else MAX_COMPRESSED_LAYER
                if member.size < 0 or member.size > limit:
                    fail(f"OCI archive member exceeds size limit: {member.name}")
                stream = archive.extractfile(member)
                if stream is None:
                    fail(f"unreadable OCI archive member: {member.name}")
                data = stream.read(limit + 1)
                if len(data) != member.size or len(data) > limit:
                    fail(f"OCI archive member size mismatch: {member.name}")
                members[name] = data
    except (tarfile.TarError, OSError) as error:
        fail(f"invalid OCI archive: {error}")
    layout = object_json(members.get("oci-layout", b"null"), "OCI layout marker")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        fail("invalid or missing OCI layout marker")
    index = object_json(members.get("index.json", b"null"), "OCI index")
    exact_keys(index, {"schemaVersion", "mediaType", "manifests"}, {"annotations"}, "OCI index")
    if index["schemaVersion"] != 2 or index["mediaType"] != INDEX_MEDIA:
        fail("unsupported OCI index schema")
    if not isinstance(index["manifests"], list) or len(index["manifests"]) != 1:
        fail("OCI archive must contain exactly one manifest")
    return index, members


def blob(value: dict[str, Any], members: dict[str, bytes], maximum: int) -> bytes:
    name = f"blobs/sha256/{value['digest'].split(':', 1)[1]}"
    data = members.get(name)
    if data is None or len(data) > maximum:
        fail(f"missing or oversized OCI blob: {value['digest']}")
    if len(data) != value["size"] or sha256_bytes(data) != value["digest"]:
        fail(f"OCI descriptor verification failed: {value['digest']}")
    return data


def safe_member_name(name: str, *, link: bool = False) -> None:
    if not name or "\x00" in name or len(name.encode()) > MAX_TAR_NAME:
        fail("OCI layer contains an invalid tar path encoding")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or str(path) != name.rstrip("/"):
        kind = "hardlink target" if link else "member path"
        fail(f"OCI layer contains an unsafe tar {kind}: {name}")


def validate_layer_tar(stream: tempfile.SpooledTemporaryFile[bytes], size: int) -> None:
    if size % tarfile.BLOCKSIZE:
        fail("OCI layer tar length is not block aligned")
    stream.seek(0)
    try:
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_LAYER_MEMBERS:
                fail("OCI layer tar member count exceeds limit")
            content_end = 0
            for member in members:
                safe_member_name(member.name)
                if member.islnk():
                    safe_member_name(member.linkname, link=True)
                elif member.issym():
                    if (
                        not member.linkname
                        or "\x00" in member.linkname
                        or len(member.linkname.encode()) > MAX_TAR_NAME
                    ):
                        fail("OCI layer contains an invalid symlink target")
                elif not (member.isfile() or member.isdir()):
                    fail(f"OCI layer contains unsupported tar member type: {member.name}")
                content_end = max(
                    content_end,
                    member.offset_data
                    + ((member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE)
                    * tarfile.BLOCKSIZE,
                )
            if size - content_end < 2 * tarfile.BLOCKSIZE:
                fail("OCI layer tar is truncated or lacks an end marker")
            stream.seek(content_end)
            while chunk := stream.read(CHUNK):
                if any(chunk):
                    fail("OCI layer tar contains trailing corruption")
    except (tarfile.TarError, UnicodeError, OSError) as error:
        fail(f"invalid OCI layer tar: {error}")


def diff_id(data: bytes, media_type: str) -> tuple[str, int]:
    source: io.BufferedIOBase | gzip.GzipFile
    source = (
        gzip.GzipFile(fileobj=io.BytesIO(data))
        if media_type.endswith("+gzip")
        else io.BytesIO(data)
    )
    result = hashlib.sha256()
    size = 0
    try:
        with source, tempfile.SpooledTemporaryFile(max_size=16_000_000, mode="w+b") as spool:
            while chunk := source.read(CHUNK):
                size += len(chunk)
                if size > MAX_UNCOMPRESSED_LAYER:
                    fail("OCI layer exceeds uncompressed size limit")
                result.update(chunk)
                spool.write(chunk)
            validate_layer_tar(spool, size)
    except (OSError, EOFError) as error:
        fail(f"invalid compressed OCI layer: {error}")
    return "sha256:" + result.hexdigest(), size


def inventory(path: Path) -> dict[str, Any]:
    index, members = load_archive(path)
    top = descriptor(index["manifests"][0], {MANIFEST_MEDIA}, "manifest")
    if top.get("platform") != {"architecture": "amd64", "os": "linux"}:
        fail("manifest descriptor platform must be linux/amd64")
    manifest = object_json(blob(top, members, MAX_JSON), "OCI manifest")
    exact_keys(
        manifest,
        {"schemaVersion", "mediaType", "config", "layers"},
        {"annotations"},
        "OCI manifest",
    )
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != MANIFEST_MEDIA:
        fail("unsupported OCI manifest schema")
    config_desc = descriptor(manifest["config"], {CONFIG_MEDIA}, "config")
    if "platform" in config_desc:
        fail("config descriptor must not declare a platform")
    config = object_json(blob(config_desc, members, MAX_JSON), "OCI config")
    exact_keys(
        config,
        {"architecture", "os", "config", "rootfs", "history"},
        {"created", "author", "variant"},
        "OCI config",
    )
    if config["architecture"] != "amd64" or config["os"] != "linux":
        fail("release OCI config must be linux/amd64")
    if not isinstance(config["config"], dict) or not isinstance(config["history"], list):
        fail("invalid OCI config or history")
    allowed_config = {
        "User",
        "ExposedPorts",
        "Env",
        "Entrypoint",
        "Cmd",
        "Volumes",
        "WorkingDir",
        "Labels",
        "StopSignal",
        "ArgsEscaped",
        "Shell",
        "Healthcheck",
    }
    if set(config["config"]) - allowed_config:
        fail("OCI runtime config contains unknown fields")
    history_fields = {"created", "author", "created_by", "comment", "empty_layer"}
    for entry in config["history"]:
        if not isinstance(entry, dict) or set(entry) - history_fields:
            fail("OCI history contains an invalid entry")
        if "empty_layer" in entry and not isinstance(entry["empty_layer"], bool):
            fail("OCI history empty_layer must be boolean")
        if any(
            key != "empty_layer" and not isinstance(item, str) and item is not None
            for key, item in entry.items()
        ):
            fail("OCI history values have invalid types")
    rootfs = config["rootfs"]
    if not isinstance(rootfs, dict):
        fail("OCI rootfs must be an object")
    exact_keys(rootfs, {"type", "diff_ids"}, set(), "OCI rootfs")
    layers = manifest["layers"]
    diff_ids = rootfs["diff_ids"]
    if (
        rootfs["type"] != "layers"
        or not isinstance(layers, list)
        or not layers
        or not isinstance(diff_ids, list)
        or len(diff_ids) != len(layers)
    ):
        fail("OCI config rootfs does not match manifest layers")
    records: list[dict[str, Any]] = []
    total = 0
    for position, raw_layer in enumerate(layers):
        layer = descriptor(raw_layer, LAYER_MEDIA, f"layer {position}")
        if "platform" in layer:
            fail(f"layer {position} must not declare a platform")
        compressed = blob(layer, members, MAX_COMPRESSED_LAYER)
        actual_diff_id, uncompressed_size = diff_id(compressed, layer["mediaType"])
        expected_diff_id = diff_ids[position]
        if not isinstance(expected_diff_id, str) or not DIGEST.fullmatch(expected_diff_id):
            fail(f"invalid rootfs DiffID at position {position}")
        if actual_diff_id != expected_diff_id:
            fail(f"rootfs DiffID mismatch at position {position}")
        total += uncompressed_size
        if total > MAX_UNCOMPRESSED_TOTAL:
            fail("OCI layers exceed total uncompressed size limit")
        records.append(
            {
                "digest": layer["digest"],
                "size": layer["size"],
                "media_type": layer["mediaType"],
                "diff_id": actual_diff_id,
                "uncompressed_size": uncompressed_size,
            }
        )
    expected = {"oci-layout", "index.json"}
    expected.update(f"blobs/sha256/{item['digest'].split(':', 1)[1]}" for item in layers)
    expected.update(
        {
            f"blobs/sha256/{top['digest'].split(':', 1)[1]}",
            f"blobs/sha256/{config_desc['digest'].split(':', 1)[1]}",
        }
    )
    extras = sorted(set(members) - expected)
    if extras:
        fail(f"unexpected OCI archive members: {extras}")
    return {
        "schema_version": 1,
        "archive_sha256": sha256_file(path),
        "archive_size": path.stat().st_size,
        "index_sha256": sha256_bytes(members["index.json"]),
        "manifest_digest": top["digest"],
        "manifest_size": top["size"],
        "config_digest": config_desc["digest"],
        "config_size": config_desc["size"],
        "rootfs_diff_ids": diff_ids,
        "layers": records,
        "uncompressed_layer_bytes": total,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = inventory(args.archive)
    if args.compare and result != inventory(args.compare):
        fail("independent OCI builds are not byte-identical")
    data = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output:
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data, end="")


if __name__ == "__main__":
    main()
