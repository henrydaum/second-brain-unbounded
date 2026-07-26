"""Digest-pinned, explicit promotion into the trusted computing base."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from security.artifacts import ArtifactId

TCB_ACKNOWLEDGEMENT = "I ACCEPT THAT THIS PLUGIN CAN FULLY COMPROMISE SECOND BRAIN"


class TrustError(PermissionError):
    pass


@dataclass(frozen=True)
class TrustRecord:
    plugin_id: str
    digest: str
    approved_at: str
    approved_by: str
    takes_effect_after_restart: bool = True


class TrustStore:
    """Local trust records.

    This class is intentionally absent from the plugin SDK and capability
    vocabulary.  Calling it is a local developer operation.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def records(self) -> tuple[TrustRecord, ...]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return ()
        except (OSError, json.JSONDecodeError) as exc:
            raise TrustError(f"could not read trust store: {exc}") from exc
        if not isinstance(raw, list):
            raise TrustError("trust store root must be a list")
        out = []
        for item in raw:
            try:
                record = TrustRecord(**item)
            except (TypeError, ValueError) as exc:
                raise TrustError(f"malformed trust record: {exc}") from exc
            if len(record.digest) != 64:
                raise TrustError("malformed artifact digest in trust store")
            out.append(record)
        return tuple(out)

    def is_promoted(self, identity: ArtifactId) -> bool:
        return any(item.plugin_id == identity.plugin_id
                   and item.digest == identity.digest
                   for item in self.records())

    def promote(self, identity: ArtifactId, *, approved_by: str,
                acknowledgement: str) -> TrustRecord:
        if acknowledgement != TCB_ACKNOWLEDGEMENT:
            raise TrustError("the full-compromise acknowledgement did not match")
        if not approved_by.strip():
            raise TrustError("approved_by is required")
        record = TrustRecord(
            plugin_id=identity.plugin_id,
            digest=identity.digest,
            approved_at=datetime.now(timezone.utc).isoformat(),
            approved_by=approved_by.strip(),
        )
        records = [item for item in self.records()
                   if item.plugin_id != identity.plugin_id]
        records.append(record)
        self._atomic_write([asdict(item) for item in records])
        return record

    def revoke(self, plugin_id: str) -> bool:
        records = list(self.records())
        kept = [item for item in records if item.plugin_id != plugin_id]
        if len(kept) == len(records):
            return False
        self._atomic_write([asdict(item) for item in kept])
        return True

    def _atomic_write(self, data: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, raw_path = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent)
        temp = Path(raw_path)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(data, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

