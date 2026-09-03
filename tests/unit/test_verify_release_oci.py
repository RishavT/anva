from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import tarfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _module() -> ModuleType:
    path = Path(__file__).parents[2] / "scripts" / "verify_release_oci.py"
    spec = importlib.util.spec_from_file_location("verify_release_oci", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


OCI = _module()
Mutation = Callable[[dict[str, Any]], None]


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _descriptor(media_type: str, data: bytes) -> dict[str, object]:
    return {"mediaType": media_type, "digest": _digest(data), "size": len(data)}


def _layer_tar(payload: bytes, name: str = "file.txt") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo(name)
        member.size = len(payload)
        member.mode = 0o644
        member.mtime = 0
        archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def _archive(
    path: Path,
    *,
    config_mutation: Mutation | None = None,
    manifest_mutation: Mutation | None = None,
    index_mutation: Mutation | None = None,
    layer_data: bytes | list[bytes] = b"deterministic layer\n",
    layer_media: str = "application/vnd.oci.image.layer.v1.tar+gzip",
    encoded_layer: bytes | None = None,
    raw_layer_tar: bytes | None = None,
    extra: tuple[str, bytes] | None = None,
    special: tarfile.TarInfo | None = None,
) -> None:
    payloads = [layer_data] if isinstance(layer_data, bytes) else layer_data
    layer_values = (
        [raw_layer_tar]
        if raw_layer_tar is not None
        else [_layer_tar(value, f"file-{position}.txt") for position, value in enumerate(payloads)]
    )
    encoded_values = (
        [encoded_layer]
        if encoded_layer is not None
        else [gzip.compress(value, mtime=0) for value in layer_values]
    )
    config: dict[str, Any] = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [_digest(value) for value in layer_values]},
        "history": [],
    }
    if config_mutation:
        config_mutation(config)
    config_data = _json(config)
    manifest: dict[str, Any] = {
        "schemaVersion": 2,
        "mediaType": OCI.MANIFEST_MEDIA,
        "config": _descriptor(OCI.CONFIG_MEDIA, config_data),
        "layers": [_descriptor(layer_media, value) for value in encoded_values],
    }
    if manifest_mutation:
        manifest_mutation(manifest)
    manifest_data = _json(manifest)
    index: dict[str, Any] = {
        "schemaVersion": 2,
        "mediaType": OCI.INDEX_MEDIA,
        "manifests": [_descriptor(OCI.MANIFEST_MEDIA, manifest_data)],
    }
    index["manifests"][0]["platform"] = {"architecture": "amd64", "os": "linux"}
    if index_mutation:
        index_mutation(index)
    files = {
        "oci-layout": _json({"imageLayoutVersion": "1.0.0"}),
        "index.json": _json(index),
        f"blobs/sha256/{_digest(manifest_data).split(':')[1]}": manifest_data,
        f"blobs/sha256/{_digest(config_data).split(':')[1]}": config_data,
    }
    files.update(
        {f"blobs/sha256/{_digest(value).split(':')[1]}": value for value in encoded_values}
    )
    if extra:
        files[extra[0]] = extra[1]
    with tarfile.open(path, "w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if special:
            archive.addfile(special)


def _rejected(path: Path) -> None:
    with pytest.raises(SystemExit):
        OCI.inventory(path)


def test_valid_minimal_oci_and_changed_input_sensitivity(tmp_path: Path) -> None:
    first = tmp_path / "first.tar"
    same = tmp_path / "same.tar"
    changed = tmp_path / "changed.tar"
    _archive(first)
    _archive(same)
    _archive(changed, layer_data=b"changed build input\n")

    assert OCI.inventory(first) == OCI.inventory(same)
    assert OCI.inventory(first)["manifest_digest"] != OCI.inventory(changed)["manifest_digest"]
    assert OCI.inventory(first)["config_digest"] != OCI.inventory(changed)["config_digest"]
    assert OCI.inventory(first)["archive_sha256"] != OCI.inventory(changed)["archive_sha256"]


@pytest.mark.parametrize("kind", ["traversal", "symlink", "hardlink", "duplicate", "extra"])
def test_rejects_unsafe_or_unexpected_members(tmp_path: Path, kind: str) -> None:
    path = tmp_path / f"{kind}.tar"
    if kind == "extra":
        _archive(path, extra=("unexpected", b"x"))
    elif kind == "duplicate":
        _archive(path, special=tarfile.TarInfo("index.json"))
    else:
        member = tarfile.TarInfo("../escape" if kind == "traversal" else "link")
        if kind == "symlink":
            member.type, member.linkname = tarfile.SYMTYPE, "index.json"
        elif kind == "hardlink":
            member.type, member.linkname = tarfile.LNKTYPE, "index.json"
        _archive(path, special=member)
    _rejected(path)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.__setitem__("schemaVersion", 1),
        lambda value: value.__setitem__("mediaType", "application/json"),
        lambda value: value.__setitem__("unknown", True),
        lambda value: value.__setitem__("manifests", []),
        lambda value: value["manifests"][0].__setitem__("digest", "sha256:nope"),
        lambda value: value["manifests"][0].__setitem__("size", -1),
    ],
)
def test_rejects_malformed_index_or_descriptor(tmp_path: Path, mutation: Mutation) -> None:
    path = tmp_path / "bad-index.tar"
    _archive(path, index_mutation=mutation)
    _rejected(path)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.__setitem__("mediaType", "application/json"),
        lambda value: value.__setitem__("layers", "not-a-list"),
        lambda value: value.__setitem__("unknown", True),
        lambda value: value["config"].__setitem__("size", 0),
        lambda value: value["config"].__setitem__("mediaType", "text/plain"),
    ],
)
def test_rejects_malformed_manifest(tmp_path: Path, mutation: Mutation) -> None:
    path = tmp_path / "bad-manifest.tar"
    _archive(path, manifest_mutation=mutation)
    _rejected(path)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.__setitem__("architecture", "arm64"),
        lambda value: value.__setitem__("unknown", True),
        lambda value: value.__setitem__("history", "bad"),
        lambda value: value["rootfs"].__setitem__("type", "unknown"),
        lambda value: value["rootfs"].__setitem__("diff_ids", []),
        lambda value: value["rootfs"].__setitem__("diff_ids", ["sha256:" + "0" * 64]),
    ],
)
def test_rejects_malformed_config_and_diffids(tmp_path: Path, mutation: Mutation) -> None:
    path = tmp_path / "bad-config.tar"
    _archive(path, config_mutation=mutation)
    _rejected(path)


def test_rejects_wrong_layer_media_type_and_corrupt_gzip(tmp_path: Path) -> None:
    wrong = tmp_path / "wrong-media.tar"
    corrupt = tmp_path / "corrupt.tar"
    _archive(wrong, layer_media="application/vnd.oci.image.layer.v1.tar+zstd")
    _archive(corrupt, encoded_layer=b"not gzip")
    _rejected(wrong)
    _rejected(corrupt)


def test_rejects_non_tar_truncation_trailing_corruption_and_unsafe_hardlink(
    tmp_path: Path,
) -> None:
    valid = _layer_tar(b"payload")
    hardlink_stream = io.BytesIO()
    with tarfile.open(fileobj=hardlink_stream, mode="w") as archive:
        member = tarfile.TarInfo("safe")
        member.type = tarfile.LNKTYPE
        member.linkname = "../escape"
        archive.addfile(member)
    cases = {
        "non-tar": b"x" * 1024,
        "truncated": valid[: 3 * tarfile.BLOCKSIZE],
        "trailing": valid + b"x" * 512,
        "hardlink": hardlink_stream.getvalue(),
    }
    for name, layer in cases.items():
        path = tmp_path / f"{name}.tar"
        _archive(path, raw_layer_tar=layer)
        _rejected(path)


def test_allows_inert_relative_symlink_targets(tmp_path: Path) -> None:
    layer_stream = io.BytesIO()
    with tarfile.open(fileobj=layer_stream, mode="w") as archive:
        member = tarfile.TarInfo("usr/lib/example-link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../lib/example-target"
        archive.addfile(member)
    path = tmp_path / "symlink.tar"
    _archive(path, raw_layer_tar=layer_stream.getvalue())
    assert OCI.inventory(path)["layers"]


def test_rejects_decompression_limit_and_diffid_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bomb = tmp_path / "bomb.tar"
    _archive(bomb, layer_data=b"x" * 1024)
    monkeypatch.setattr(OCI, "MAX_UNCOMPRESSED_LAYER", 128)
    _rejected(bomb)


def test_rejects_diffid_order_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "order.tar"

    def reverse(value: dict[str, Any]) -> None:
        value["rootfs"]["diff_ids"].reverse()

    _archive(path, layer_data=[b"first", b"second"], config_mutation=reverse)
    _rejected(path)
