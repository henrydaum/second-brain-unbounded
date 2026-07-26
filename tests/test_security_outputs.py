import asyncio

from pipeline.database import Database
from plugin_sdk import InvocationContext, ResourceHandle
from runtime.plugin_security import build_plugin_security
from security.broker import LocalCapabilityTransport
from security.capabilities import AuthorityContext, ProvenanceChain
from security.manifest import load_manifest


def test_attachment_is_copied_and_returned_as_opaque_handle(tmp_path):
    manifest_path = tmp_path / "plugin.toml"
    manifest_path.write_text("""
schema_version = 1
id = "example.output"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "output"
entrypoint = "plugin:run"

[[capabilities]]
right = "outputs.attach"
resource = "work/*"
""", encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()
    source = work / "report.txt"
    source.write_text("immutable result", encoding="utf-8")
    security = build_plugin_security(
        Database(tmp_path / "db.sqlite"),
        artifact_root=tmp_path / "missing",
        helper=tmp_path / "missing-helper",
        trust_store_path=tmp_path / "trust.json",
    )
    digest = "a" * 64
    authority = AuthorityContext(
        artifact_digest=digest,
        principal="agent",
        provenance=ProvenanceChain("agent").enter(digest, "tool:output"),
        user_id=7,
        session_key="s",
    )
    ref = security.resources.issue(
        artifact_digest=digest,
        principal="agent",
        rights={"outputs.attach"},
        selector="work/*",
        alias="work",
        user_id=7,
        session_key="s",
        binding=work,
    )
    ctx = InvocationContext(
        LocalCapabilityTransport(
            security.broker,
            invocation_id="output",
            manifest=load_manifest(manifest_path),
            authority=authority,
        ),
        resources={"work": ResourceHandle(ref.token, "work")},
    )

    handle = asyncio.run(ctx.outputs.attach(
        ctx.resources["work"], "report.txt"))
    assert "path" not in handle
    attachment = security.attachments.resolve(
        handle["attachment"], authority)
    assert attachment is not None
    assert attachment.path != source
    source.write_text("changed", encoding="utf-8")
    assert attachment.path.read_text(encoding="utf-8") == "immutable result"
    security.close()
