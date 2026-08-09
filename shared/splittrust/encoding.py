import base64
import hashlib
import json
from typing import Any


def b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def canonical_json(value: Any) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()
