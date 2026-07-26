import asyncio
from types import SimpleNamespace

import pytest

from pipeline.database import Database
from plugin_sdk import InvocationContext, ResourceHandle
from runtime.plugin_security import build_plugin_security
from security.broker import LocalCapabilityTransport
from security.capabilities import (
    AuthorityContext,
    DataLabel,
    GrantLease,
    ProvenanceChain,
)
from security.manifest import load_manifest


def _manifest(tmp_path):
    path = tmp_path / "plugin.toml"
    path.write_text("""
schema_version = 1
id = "example.views"
version = "1"
runtime = "python"

[[handlers]]
kind = "tool"
name = "view"
entrypoint = "plugin:run"

[[capabilities]]
right = "data.read"
resource = "conversation"
labels = ["user-private"]
""", encoding="utf-8")
    return load_manifest(path)


def test_conversation_views_are_selected_from_kernel_identity(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    own = db.create_conversation("own", user_id=7)
    other = db.create_conversation("other", user_id=8)
    security = build_plugin_security(
        db, artifact_root=tmp_path / "missing",
        helper=tmp_path / "missing-helper")
    runtime = SimpleNamespace(
        db=db,
        assert_conversation_access=lambda session, cid: cid == own,
    )
    security.bind_runtime(runtime)
    digest = "a" * 64
    authority = AuthorityContext(
        artifact_digest=digest,
        principal="agent",
        provenance=ProvenanceChain("agent").enter(digest, "tool:view"),
        user_id=7,
        session_key="s",
        conversation_id=own,
    )
    ref = security.issue_plugin_data(
        artifact_digest=digest,
        principal="agent",
        namespace="unused",
        selector="conversation",
        alias="conversation",
        rights={"data.read"},
        allowed_views={
            "conversation.current", "conversation.messages",
            "conversations.list",
        },
        user_id=7,
        session_key="s",
        conversation_id=own,
    )
    security.leases.add(GrantLease.create(
        artifact_digest=digest,
        principal="agent",
        right="data.read",
        resource_selector="conversation",
        allowed_labels=frozenset({
            DataLabel.PUBLIC, DataLabel.USER_PRIVATE}),
        user_id=7,
        session_key="s",
        conversation_id=own,
        remaining_uses=None,
    ))
    ctx = InvocationContext(
        LocalCapabilityTransport(
            security.broker,
            invocation_id="view",
            manifest=_manifest(tmp_path),
            authority=authority,
        ),
        resources={
            "conversation": ResourceHandle(ref.token, ref.selector),
        },
    )

    current = asyncio.run(ctx.data.view(
        ctx.resources["conversation"],
        "conversation.current",
        {"conversation_id": other},
    ))
    listed = asyncio.run(ctx.data.view(
        ctx.resources["conversation"], "conversations.list", {"limit": 50}))
    assert current["id"] == own
    assert {item["id"] for item in listed} == {own}
    security.close()


def test_current_conversation_view_rejects_missing_session_identity(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    security = build_plugin_security(
        db, artifact_root=tmp_path / "missing",
        helper=tmp_path / "missing-helper")
    security.bind_runtime(SimpleNamespace(
        db=db, assert_conversation_access=lambda *_: True))
    with pytest.raises(PermissionError, match="current conversation"):
        security.views.read(
            "conversation.current",
            AuthorityContext(
                artifact_digest="a" * 64,
                principal="agent",
                provenance=ProvenanceChain("agent"),
            ),
            {},
        )
    security.close()
