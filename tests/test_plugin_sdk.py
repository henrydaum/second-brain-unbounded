import asyncio

import pytest

from plugin_sdk import FakeBroker, InvocationContext, ResourceHandle
from plugin_sdk.context import CapabilityDenied


def test_async_sdk_is_plain_python_and_records_typed_requests():
    async def scenario():
        broker = FakeBroker()
        broker.handle("files.read", lambda p: f"read:{p['selector']}")
        ctx = InvocationContext(
            broker, resources={"notes": ResourceHandle("opaque", "notes")})
        value = await ctx.files.read_text(ctx.resources["notes"], "a.md")
        assert value == "read:notes/a.md"
        assert broker.requests[0][0] == "files.read"
        assert broker.requests[0][1]["resource"] == "opaque"
    asyncio.run(scenario())


def test_sdk_refuses_selector_parent_traversal_before_rpc():
    async def scenario():
        broker = FakeBroker()
        ctx = InvocationContext(broker)
        with pytest.raises(ValueError, match=r"\.\."):
            await ctx.files.read_text(ResourceHandle("x", "notes"), "../secret")
        assert broker.requests == []
    asyncio.run(scenario())


def test_fake_broker_denial_becomes_exception():
    async def scenario():
        ctx = InvocationContext(FakeBroker())
        with pytest.raises(CapabilityDenied):
            await ctx.runtime.ask_user("hello")
    asyncio.run(scenario())

