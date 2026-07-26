import json

import pytest

from plugin_sdk import InvocationContext, ResourceHandle
from plugin_sdk.context import CapabilityDenied
from security.broker import CapabilityBroker, LocalCapabilityTransport
from security.capabilities import (
    AuthorityContext,
    DataLabel,
    LeaseStore,
    PolicyEngine,
    ProvenanceChain,
    ResourceRegistry,
)
from security.file_adapter import FileCapabilityAdapter
from security.file_journal import DurableFileJournal
from security.manifest import load_manifest


def _manifest(tmp_path):
    path = tmp_path / "plugin.toml"
    path.write_text("""
schema_version = 1
id = "example.files"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "writer"
entrypoint = "plugin:run"

[[capabilities]]
right = "files.write"
resource = "notes/*"

[[capabilities]]
right = "files.delete"
resource = "notes/*"

[[capabilities]]
right = "files.list"
resource = "notes/*"

[[capabilities]]
right = "files.stat"
resource = "notes/*"

[[capabilities]]
right = "files.move"
resource = "notes/*"
""", encoding="utf-8")
    return load_manifest(path)


def _runtime(tmp_path):
    digest = "a" * 64
    resources = ResourceRegistry()
    notes = tmp_path / "notes"
    notes.mkdir()
    ref = resources.issue(
        artifact_digest=digest, principal="agent",
        rights={
            "files.write", "files.delete", "files.list", "files.stat",
            "files.move",
        }, selector="notes/*",
        binding=notes)
    journal = DurableFileJournal(tmp_path / "journal")
    adapter = FileCapabilityAdapter(resources, journal)
    broker = CapabilityBroker(PolicyEngine(resources, LeaseStore()))
    broker.register("files.write", adapter.prepare_write)
    broker.register("files.delete", adapter.prepare_delete)
    broker.register("files.list", adapter.prepare_list)
    broker.register("files.stat", adapter.prepare_stat)
    broker.register("files.move", adapter.prepare_move)
    authority = AuthorityContext(
        artifact_digest=digest, principal="agent",
        provenance=ProvenanceChain("agent").enter(digest, "tool:writer"))
    transport = LocalCapabilityTransport(
        broker, invocation_id="i", manifest=_manifest(tmp_path),
        authority=authority)
    return InvocationContext(
        transport, resources={"notes": ResourceHandle(ref.token, "notes")}), journal


def test_brokered_write_records_inverse_before_visibility(tmp_path):
    import asyncio
    ctx, journal = _runtime(tmp_path)
    target = tmp_path / "notes" / "a.txt"
    target.write_text("before", encoding="utf-8")
    result = asyncio.run(
        ctx.files.write_text(ctx.resources["notes"], "a.txt", "after"))
    assert target.read_text(encoding="utf-8") == "after"
    record = json.loads(
        (journal.root / result["transaction_id"] / "intent.json").read_text())
    assert record["status"] == "committed"
    assert (journal.root / result["transaction_id"] / "before.bin").read_text() == "before"


def test_recovery_rolls_back_interrupted_apply(tmp_path):
    journal = DurableFileJournal(tmp_path / "journal")
    target = tmp_path / "a.txt"
    target.write_text("before", encoding="utf-8")
    mutation = journal.prepare(target)
    journal._mark(mutation, "applying")
    target.write_text("half-applied", encoding="utf-8")
    assert journal.recover_incomplete() == [mutation.transaction_id]
    assert target.read_text(encoding="utf-8") == "before"


def test_denied_write_discards_prepared_inverse_without_mutation(tmp_path):
    import asyncio
    ctx, journal = _runtime(tmp_path)
    # A changed opaque token is denied by policy after the adapter prepares no
    # real target, and no journal directory or destination appears.
    bad = ResourceHandle("forged", "notes")
    with pytest.raises(CapabilityDenied):
        asyncio.run(
            ctx.files._call(
                "files.write", resource=bad.token, selector="notes/x",
                content="no", encoding="utf-8"))
    assert not (tmp_path / "notes" / "x").exists()
    assert list(journal.root.iterdir()) == []


def test_list_stat_and_move_stay_inside_resource(tmp_path):
    import asyncio
    ctx, journal = _runtime(tmp_path)
    source = tmp_path / "notes" / "source.txt"
    destination = tmp_path / "notes" / "nested" / "destination.txt"
    source.write_text("source", encoding="utf-8")
    handle = ctx.resources["notes"]

    rows = asyncio.run(ctx.files.list(handle))
    assert rows == [{
        "name": "source.txt",
        "kind": "file",
        "size": 6,
        "modified_ns": source.stat().st_mtime_ns,
    }]
    assert asyncio.run(ctx.files.stat(handle, "source.txt"))["size"] == 6
    moved = asyncio.run(ctx.files.move(
        handle, "source.txt", "nested/destination.txt"))
    assert not source.exists()
    assert destination.read_text(encoding="utf-8") == "source"

    move, status = journal._load_move(
        journal.root / moved["transaction_id"],
        json.loads((journal.root / moved["transaction_id"]
                    / "intent.json").read_text()),
    )
    assert status == "committed"
    move.rollback()
    assert source.read_text(encoding="utf-8") == "source"
    assert not destination.exists()
    assert not destination.parent.exists()


def test_recovery_rolls_back_interrupted_move(tmp_path):
    journal = DurableFileJournal(tmp_path / "journal")
    source = tmp_path / "source.txt"
    destination = tmp_path / "destination.txt"
    source.write_text("source", encoding="utf-8")
    destination.write_text("prior", encoding="utf-8")
    mutation = journal.prepare_move(source, destination)
    journal._mark_move(mutation, "applying")
    source.replace(destination)

    assert journal.recover_incomplete() == [mutation.transaction_id]
    assert source.read_text(encoding="utf-8") == "source"
    assert destination.read_text(encoding="utf-8") == "prior"
