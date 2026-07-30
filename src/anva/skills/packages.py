"""Build reproducible, inert host distribution archives."""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
import tempfile
from pathlib import Path

from anva.skills.contracts import load_distribution


def _archive_bytes(source: Path, root_name: str) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(source.rglob("*")):
                if path.is_symlink():
                    raise ValueError(f"Refusing symlink in distribution: {path}")
                if not path.is_file():
                    continue
                relative = path.relative_to(source).as_posix()
                data = path.read_bytes()
                info = tarfile.TarInfo(f"{root_name}/{relative}")
                info.size = len(data)
                info.mode = 0o644
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def build_distributions(package_root: Path, output: Path) -> dict[str, str]:
    """Write deterministic Codex and Claude archives plus SHA256SUMS."""
    root = package_root.resolve()
    distribution = load_distribution(root)
    output.mkdir(parents=True, exist_ok=True)
    result: dict[str, str] = {}
    for host in ("codex", "claude"):
        filename = f"anva-{host}-skills-{distribution.skill_version}.tar.gz"
        source = root / "generated" / f"{host}-plugin"
        if not source.is_dir():
            raise ValueError(f"Generated {host} package is missing")
        payload = _archive_bytes(source, f"anva-{host}")
        (output / filename).write_bytes(payload)
        result[filename] = hashlib.sha256(payload).hexdigest()
    sums = "".join(f"{digest}  {name}\n" for name, digest in sorted(result.items()))
    (output / "SHA256SUMS").write_text(sums, encoding="utf-8")
    return result


def verify_distributions(output: Path) -> dict[str, object]:
    """Verify checksums and reject unsafe archive members."""
    checksum_file = output / "SHA256SUMS"
    if not checksum_file.is_file() or checksum_file.is_symlink():
        raise ValueError("SHA256SUMS is missing or unsafe")
    verified: list[str] = []
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        digest, separator, filename = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not filename
            or Path(filename).name != filename
        ):
            raise ValueError("SHA256SUMS contains an invalid entry")
        archive_path = output / filename
        if not archive_path.is_file() or archive_path.is_symlink():
            raise ValueError(f"Archive is missing or unsafe: {filename}")
        actual = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"Checksum mismatch: {filename}")
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive.getmembers():
                parts = Path(member.name).parts
                if (
                    member.name.startswith("/")
                    or ".." in parts
                    or member.issym()
                    or member.islnk()
                    or not member.isfile()
                ):
                    raise ValueError(f"Unsafe archive member: {member.name}")
        verified.append(filename)
    return {"status": "verified", "archives": verified}


def check_distributions(package_root: Path, output: Path) -> list[str]:
    """Return committed artifact paths that differ from a fresh deterministic build."""
    with tempfile.TemporaryDirectory(prefix="anva-package-check-") as temporary:
        candidate = Path(temporary)
        build_distributions(package_root, candidate)
        names = {path.name for path in candidate.iterdir() if path.is_file()} | {
            path.name for path in output.iterdir() if path.is_file()
        }
        return [
            str(output / name)
            for name in sorted(names)
            if not (output / name).is_file()
            or not (candidate / name).is_file()
            or (output / name).read_bytes() != (candidate / name).read_bytes()
        ]
