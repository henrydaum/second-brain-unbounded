"""Crash-safe inverse records for brokered filesystem mutations."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


class FileJournalError(RuntimeError):
    pass


@dataclass
class PreparedFileMutation:
    transaction_id: str
    directory: Path
    target: Path
    existed: bool
    backup: Path | None
    journal: "DurableFileJournal"
    created_parents: tuple[Path, ...] = ()
    applied: bool = False

    def write(self, content: bytes) -> dict:
        self.journal._mark(self, "applying")
        self.target.parent.mkdir(parents=True, exist_ok=True)
        fd, raw_temp = tempfile.mkstemp(
            prefix=self.target.name + ".", suffix=".sb-tmp",
            dir=self.target.parent)
        temp = Path(raw_temp)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.target)
            _fsync_dir(self.target.parent)
            self.applied = True
            self.journal._mark(self, "committed")
            return {
                "transaction_id": self.transaction_id,
                "bytes": len(content),
                "path": str(self.target),
            }
        except Exception:
            try:
                self.rollback()
            finally:
                try:
                    temp.unlink()
                except FileNotFoundError:
                    pass
            raise

    def delete(self) -> dict:
        self.journal._mark(self, "applying")
        try:
            if self.target.exists():
                if not self.target.is_file():
                    raise FileJournalError("transactional delete supports files only")
                self.target.unlink()
                _fsync_dir(self.target.parent)
            self.applied = True
            self.journal._mark(self, "committed")
            return {
                "transaction_id": self.transaction_id,
                "existed": self.existed,
                "path": str(self.target),
            }
        except Exception:
            self.rollback()
            raise

    def rollback(self) -> None:
        if self.existed:
            if self.backup is None or not self.backup.is_file():
                raise FileJournalError("inverse backup is missing")
            self.target.parent.mkdir(parents=True, exist_ok=True)
            fd, raw_temp = tempfile.mkstemp(
                prefix=self.target.name + ".", suffix=".sb-restore",
                dir=self.target.parent)
            temp = Path(raw_temp)
            try:
                with os.fdopen(fd, "wb") as stream:
                    with self.backup.open("rb") as source:
                        shutil.copyfileobj(source, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, self.target)
                _fsync_dir(self.target.parent)
            finally:
                try:
                    temp.unlink()
                except FileNotFoundError:
                    pass
        else:
            try:
                self.target.unlink()
                _fsync_dir(self.target.parent)
            except FileNotFoundError:
                pass
        _remove_empty(self.created_parents)
        self.applied = False
        self.journal._mark(self, "rolled_back")

    def abort(self) -> None:
        """Discard a prepared inverse when policy denies before enactment."""
        if self.applied:
            self.rollback()
        shutil.rmtree(self.directory, ignore_errors=True)


@dataclass
class PreparedFileMove:
    transaction_id: str
    directory: Path
    source: Path
    destination: Path
    source_backup: Path
    destination_existed: bool
    destination_backup: Path | None
    journal: "DurableFileJournal"
    created_parents: tuple[Path, ...] = ()
    applied: bool = False

    def move(self) -> dict:
        self.journal._mark_move(self, "applying")
        try:
            self.destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(self.source, self.destination)
            _fsync_dir(self.source.parent)
            if self.destination.parent != self.source.parent:
                _fsync_dir(self.destination.parent)
            self.applied = True
            self.journal._mark_move(self, "committed")
            return {
                "transaction_id": self.transaction_id,
                "source": str(self.source),
                "destination": str(self.destination),
            }
        except Exception:
            self.rollback()
            raise

    def rollback(self) -> None:
        _restore_backup(self.source_backup, self.source)
        if self.destination_existed:
            if self.destination_backup is None:
                raise FileJournalError("destination inverse backup is missing")
            _restore_backup(self.destination_backup, self.destination)
        else:
            try:
                self.destination.unlink()
                _fsync_dir(self.destination.parent)
            except FileNotFoundError:
                pass
        _remove_empty(self.created_parents)
        self.applied = False
        self.journal._mark_move(self, "rolled_back")

    def abort(self) -> None:
        if self.applied:
            self.rollback()
        shutil.rmtree(self.directory, ignore_errors=True)


class DurableFileJournal:
    """Content-addressed inverse journal.

    A ``prepared`` record and any prior bytes are fsynced before the caller
    receives a mutation object.  ``applying`` records are rolled back on
    recovery; ``committed`` records remain available for turn-level undo.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def prepare(self, target: str | Path) -> PreparedFileMutation:
        resolved = Path(target).resolve()
        existed = resolved.exists()
        if existed and not resolved.is_file():
            raise FileJournalError("transactional mutations support files only")
        transaction_id = f"{int(time.time() * 1000):x}-{secrets.token_hex(12)}"
        directory = self.root / transaction_id
        directory.mkdir(parents=False)
        backup = directory / "before.bin" if existed else None
        if backup is not None:
            _copy_fsync(resolved, backup)
        mutation = PreparedFileMutation(
            transaction_id=transaction_id,
            directory=directory,
            target=resolved,
            existed=existed,
            backup=backup,
            journal=self,
            created_parents=_missing_parents(resolved.parent),
        )
        self._mark(mutation, "prepared")
        _fsync_dir(self.root)
        return mutation

    def prepare_move(
        self,
        source: str | Path,
        destination: str | Path,
    ) -> PreparedFileMove:
        source = Path(source).resolve()
        destination = Path(destination).resolve()
        if source == destination:
            raise FileJournalError("move source and destination are identical")
        if not source.is_file():
            raise FileJournalError("move source must be an existing file")
        if destination.exists() and not destination.is_file():
            raise FileJournalError("move destination must be a file or absent")
        transaction_id = f"{int(time.time() * 1000):x}-{secrets.token_hex(12)}"
        directory = self.root / transaction_id
        directory.mkdir(parents=False)
        source_backup = directory / "source-before.bin"
        _copy_fsync(source, source_backup)
        destination_existed = destination.exists()
        destination_backup = (
            directory / "destination-before.bin"
            if destination_existed else None)
        if destination_backup is not None:
            _copy_fsync(destination, destination_backup)
        move = PreparedFileMove(
            transaction_id=transaction_id,
            directory=directory,
            source=source,
            destination=destination,
            source_backup=source_backup,
            destination_existed=destination_existed,
            destination_backup=destination_backup,
            journal=self,
            created_parents=_missing_parents(destination.parent),
        )
        self._mark_move(move, "prepared")
        _fsync_dir(self.root)
        return move

    def recover_incomplete(self) -> list[str]:
        recovered: list[str] = []
        if not self.root.exists():
            return recovered
        for directory in sorted(self.root.iterdir()):
            if not directory.is_dir():
                continue
            try:
                raw = json.loads(
                    (directory / "intent.json").read_text(encoding="utf-8"))
                if raw.get("operation") == "move":
                    mutation, status = self._load_move(directory, raw)
                else:
                    mutation, status = self._load(directory, raw)
            except Exception:
                # A malformed inverse is retained for operator inspection.  It
                # is never guessed at or silently deleted.
                continue
            if status in {"prepared"}:
                mutation.abort()
                recovered.append(mutation.transaction_id)
            elif status == "applying":
                mutation.applied = True
                mutation.rollback()
                recovered.append(mutation.transaction_id)
        return recovered

    def _mark(self, mutation: PreparedFileMutation, status: str) -> None:
        payload = {
            "version": 1,
            "operation": "mutation",
            "transaction_id": mutation.transaction_id,
            "target": str(mutation.target),
            "existed": mutation.existed,
            "backup": mutation.backup.name if mutation.backup else None,
            "backup_sha256": (
                _sha256(mutation.backup) if mutation.backup else None),
            "status": status,
            "created_parents": [
                str(item) for item in mutation.created_parents],
            "updated_at": time.time(),
        }
        self._write_intent(mutation.directory, payload)

    def _mark_move(self, mutation: PreparedFileMove, status: str) -> None:
        payload = {
            "version": 1,
            "operation": "move",
            "transaction_id": mutation.transaction_id,
            "source": str(mutation.source),
            "destination": str(mutation.destination),
            "source_backup": mutation.source_backup.name,
            "source_backup_sha256": _sha256(mutation.source_backup),
            "destination_existed": mutation.destination_existed,
            "destination_backup": (
                mutation.destination_backup.name
                if mutation.destination_backup else None),
            "destination_backup_sha256": (
                _sha256(mutation.destination_backup)
                if mutation.destination_backup else None),
            "status": status,
            "created_parents": [
                str(item) for item in mutation.created_parents],
            "updated_at": time.time(),
        }
        self._write_intent(mutation.directory, payload)

    @staticmethod
    def _write_intent(directory: Path, payload: dict) -> None:
        temp = directory / "intent.json.tmp"
        final = directory / "intent.json"
        with temp.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, final)
        _fsync_dir(directory)

    def _load(
        self,
        directory: Path,
        raw: dict | None = None,
    ) -> tuple[PreparedFileMutation, str]:
        raw = raw or json.loads(
            (directory / "intent.json").read_text(encoding="utf-8"))
        if raw.get("version") != 1 or raw.get("transaction_id") != directory.name:
            raise FileJournalError("invalid inverse record")
        backup = directory / raw["backup"] if raw.get("backup") else None
        if backup is not None and _sha256(backup) != raw.get("backup_sha256"):
            raise FileJournalError("inverse backup digest mismatch")
        mutation = PreparedFileMutation(
            transaction_id=directory.name,
            directory=directory,
            target=Path(raw["target"]),
            existed=bool(raw["existed"]),
            backup=backup,
            journal=self,
            created_parents=tuple(
                Path(item) for item in raw.get("created_parents", [])),
        )
        return mutation, str(raw.get("status"))

    def _load_move(
        self,
        directory: Path,
        raw: dict,
    ) -> tuple[PreparedFileMove, str]:
        if raw.get("version") != 1 or raw.get("transaction_id") != directory.name:
            raise FileJournalError("invalid move inverse record")
        source_backup = directory / str(raw["source_backup"])
        if _sha256(source_backup) != raw.get("source_backup_sha256"):
            raise FileJournalError("source inverse backup digest mismatch")
        destination_backup = (
            directory / str(raw["destination_backup"])
            if raw.get("destination_backup") else None)
        if (destination_backup is not None
                and _sha256(destination_backup)
                != raw.get("destination_backup_sha256")):
            raise FileJournalError("destination inverse backup digest mismatch")
        mutation = PreparedFileMove(
            transaction_id=directory.name,
            directory=directory,
            source=Path(raw["source"]),
            destination=Path(raw["destination"]),
            source_backup=source_backup,
            destination_existed=bool(raw["destination_existed"]),
            destination_backup=destination_backup,
            journal=self,
            created_parents=tuple(
                Path(item) for item in raw.get("created_parents", [])),
        )
        return mutation, str(raw.get("status"))


def _copy_fsync(source: Path, destination: Path) -> None:
    with source.open("rb") as inp, destination.open("xb") as out:
        shutil.copyfileobj(inp, out)
        out.flush()
        os.fsync(out.fileno())


def _restore_backup(backup: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".sb-restore", dir=target.parent)
    temp = Path(raw_temp)
    try:
        with os.fdopen(fd, "wb") as stream:
            with backup.open("rb") as source:
                shutil.copyfileobj(source, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, target)
        _fsync_dir(target.parent)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _missing_parents(parent: Path) -> tuple[Path, ...]:
    missing: list[Path] = []
    current = parent
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    return tuple(missing)


def _remove_empty(paths: tuple[Path, ...]) -> None:
    for path in paths:
        try:
            path.rmdir()
            _fsync_dir(path.parent)
        except (FileNotFoundError, OSError):
            pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_dir(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
