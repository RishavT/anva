"""Small S3-compatible object-storage boundary for evidence bytes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import IO, Final
from urllib.parse import quote, urlparse

from django.conf import settings

from anva.core.services.evidence_archive import (
    DEFAULT_UPLOAD_LIMITS,
    EvidenceUploadError,
)


class EvidenceStorageError(EvidenceUploadError):
    """Sanitized object-storage boundary failure."""

    def __init__(self, code: str = "EVIDENCE_STORAGE_UNAVAILABLE") -> None:
        super().__init__(code, "Evidence object storage is unavailable.", 503)


class EvidenceObjectOwnershipConflictError(EvidenceStorageError):
    """A conditional PUT found bytes that this authorization does not own."""

    def __init__(self) -> None:
        super().__init__("EVIDENCE_STORAGE_OBJECT_EXISTS")


class EvidenceObjectNotFoundError(EvidenceStorageError):
    """The exact object key has no retained bytes."""

    def __init__(self) -> None:
        super().__init__("EVIDENCE_STORAGE_OBJECT_NOT_FOUND")


class EvidenceObjectStorage:
    """Minimal SigV4 S3-compatible CRUD for small, immutable evidence objects."""

    timeout_seconds: Final[float] = 5.0

    def __init__(self) -> None:
        endpoint = urlparse(str(settings.OBJECT_STORAGE_ENDPOINT))
        bucket = str(settings.OBJECT_STORAGE_BUCKET)
        if (
            endpoint.scheme not in {"http", "https"}
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.query
            or endpoint.fragment
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{1,62}", bucket)
        ):
            raise EvidenceStorageError("EVIDENCE_STORAGE_CONFIGURATION_INVALID")
        assert endpoint.hostname is not None
        self._endpoint = endpoint
        self._hostname = endpoint.hostname
        self._bucket = bucket

    def _path(self, object_key: str) -> str:
        if (
            not object_key.startswith("evidence/v1/")
            or ".." in PurePosixPath(object_key).parts
            or "\\" in object_key
            or "\x00" in object_key
        ):
            raise EvidenceStorageError("EVIDENCE_STORAGE_KEY_INVALID")
        base_path = self._endpoint.path.rstrip("/")
        encoded_bucket = quote(self._bucket, safe="-_.~")
        encoded_key = quote(object_key, safe="/-_.~")
        return f"{base_path}/{encoded_bucket}/{encoded_key}"

    def _connection(self) -> http.client.HTTPConnection:
        connection_class = (
            http.client.HTTPSConnection
            if self._endpoint.scheme == "https"
            else http.client.HTTPConnection
        )
        return connection_class(
            self._hostname,
            self._endpoint.port or (443 if self._endpoint.scheme == "https" else 80),
            timeout=self.timeout_seconds,
        )

    def _signed_headers(
        self,
        *,
        method: str,
        path: str,
        payload_hash: str,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        now = datetime.now(UTC)
        timestamp = now.strftime("%Y%m%dT%H%M%SZ")
        date = timestamp[:8]
        host = self._endpoint.netloc
        headers = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": timestamp,
            **{key.casefold(): value.strip() for key, value in (extra_headers or {}).items()},
        }
        signed_names = sorted(key for key in headers if key == "host" or key.startswith("x-amz-"))
        canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in signed_names)
        signed_headers = ";".join(signed_names)
        canonical_request = "\n".join(
            (method, path, "", canonical_headers, signed_headers, payload_hash)
        )
        region = str(settings.OBJECT_STORAGE_REGION)
        scope = f"{date}/{region}/s3/aws4_request"
        string_to_sign = "\n".join(
            (
                "AWS4-HMAC-SHA256",
                timestamp,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            )
        )
        date_key = hmac.new(
            f"AWS4{settings.OBJECT_STORAGE_SECRET_KEY}".encode(),
            date.encode(),
            hashlib.sha256,
        ).digest()
        region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
        service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
        signing_key = hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            "AWS4-HMAC-SHA256 "
            f"Credential={settings.OBJECT_STORAGE_ACCESS_KEY}/{scope},"
            f"SignedHeaders={signed_headers},Signature={signature}"
        )
        return {
            "-".join(part.capitalize() for part in key.split("-")): value
            for key, value in headers.items()
        }

    def put(
        self,
        *,
        object_key: str,
        stream: IO[bytes],
        size: int,
        sha256: str,
        media_type: str,
        ownership_nonce: str,
    ) -> None:
        path = self._path(object_key)
        checksum = base64.b64encode(bytes.fromhex(sha256)).decode()
        extra_headers = {
            "content-length": str(size),
            "content-type": media_type,
            "if-none-match": "*",
            "x-amz-checksum-sha256": checksum,
            "x-amz-meta-anva-sha256": sha256,
            "x-amz-meta-anva-owner": ownership_nonce,
        }
        headers = self._signed_headers(
            method="PUT",
            path=path,
            payload_hash=sha256,
            extra_headers=extra_headers,
        )
        connection = self._connection()
        try:
            stream.seek(0)
            connection.request("PUT", path, body=stream, headers=headers)
            response = connection.getresponse()
            response.read(1_024)
            if response.status == 412:
                raise EvidenceObjectOwnershipConflictError()
            if response.status not in {200, 201}:
                raise EvidenceStorageError("EVIDENCE_STORAGE_PUT_FAILED")
        except EvidenceStorageError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise EvidenceStorageError("EVIDENCE_STORAGE_PUT_FAILED") from error
        finally:
            connection.close()

    def head(self, *, object_key: str) -> tuple[int, str, str]:
        path = self._path(object_key)
        empty_hash = hashlib.sha256(b"").hexdigest()
        headers = self._signed_headers(method="HEAD", path=path, payload_hash=empty_hash)
        connection = self._connection()
        try:
            connection.request("HEAD", path, headers=headers)
            response = connection.getresponse()
            response.read(1_024)
            if response.status == 404:
                raise EvidenceObjectNotFoundError()
            if response.status != 200:
                raise EvidenceStorageError("EVIDENCE_STORAGE_HEAD_FAILED")
            length = response.getheader("Content-Length")
            digest = response.getheader("X-Amz-Meta-Anva-Sha256")
            owner = response.getheader("X-Amz-Meta-Anva-Owner")
            if length is None or digest is None or owner is None:
                raise EvidenceStorageError("EVIDENCE_STORAGE_VERIFY_FAILED")
            return int(length), digest, owner
        except EvidenceStorageError:
            raise
        except (TypeError, ValueError) as error:
            raise EvidenceStorageError("EVIDENCE_STORAGE_VERIFY_FAILED") from error
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise EvidenceStorageError("EVIDENCE_STORAGE_HEAD_FAILED") from error
        finally:
            connection.close()

    def get_digest(self, *, object_key: str, max_bytes: int) -> tuple[int, str]:
        path = self._path(object_key)
        empty_hash = hashlib.sha256(b"").hexdigest()
        headers = self._signed_headers(method="GET", path=path, payload_hash=empty_hash)
        connection = self._connection()
        digest = hashlib.sha256()
        size = 0
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if response.status != 200:
                response.read(1_024)
                raise EvidenceStorageError("EVIDENCE_STORAGE_GET_FAILED")
            while True:
                chunk = response.read(min(DEFAULT_UPLOAD_LIMITS.chunk_bytes, max_bytes - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise EvidenceStorageError("EVIDENCE_STORAGE_VERIFY_FAILED")
                digest.update(chunk)
            return size, digest.hexdigest()
        except EvidenceStorageError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise EvidenceStorageError("EVIDENCE_STORAGE_GET_FAILED") from error
        finally:
            connection.close()

    def delete(self, *, object_key: str) -> None:
        path = self._path(object_key)
        empty_hash = hashlib.sha256(b"").hexdigest()
        headers = self._signed_headers(method="DELETE", path=path, payload_hash=empty_hash)
        connection = self._connection()
        try:
            connection.request("DELETE", path, headers=headers)
            response = connection.getresponse()
            response.read(1_024)
            if response.status not in {200, 204, 404}:
                raise EvidenceStorageError("EVIDENCE_STORAGE_DELETE_FAILED")
        except EvidenceStorageError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise EvidenceStorageError("EVIDENCE_STORAGE_DELETE_FAILED") from error
        finally:
            connection.close()
