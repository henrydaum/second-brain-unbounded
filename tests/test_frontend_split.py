"""Where the frontend boundary falls — checkable, not just described.

Frontends are the one family whose split is genuine rather than mechanical:

- the **render** half is data in, side effects out, and the inbound half is
  already typed (bus events in, ``submit(session_key, action_type, payload)``
  out). It is sandboxable exactly as it stands.
- the **transport** half — ``start``/``stop``, the socket or input loop — holds a
  live handle and owns a loop, which is capabilities 1 and 2. It is a permanent
  entry on the trusted-exception list, and the kernel owns it.

These tests pin the line so it cannot blur: a render method that starts holding
a socket, or a transport method that sneaks into the render list, fails here.
"""

from __future__ import annotations

import inspect

from plugins.BaseFrontend import BaseFrontend

# Methods that own a handle or a loop. Never sandboxable, by capability.
TRANSPORT_METHODS = ("start", "stop", "bind", "unbind")


def test_every_declared_render_method_exists():
    """The list is a contract, not a comment."""
    missing = [m for m in BaseFrontend.RENDER_METHODS if not hasattr(BaseFrontend, m)]
    assert not missing, f"declared but absent: {missing}"


def test_the_render_list_covers_every_render_method():
    """A new render_* method must be added to the list deliberately — otherwise
    the sandboxable surface would grow without anyone deciding it should."""
    found = {name for name in dir(BaseFrontend)
             if name.startswith("render_") and callable(getattr(BaseFrontend, name, None))}
    undeclared = found - set(BaseFrontend.RENDER_METHODS)

    assert not undeclared, (
        f"render methods missing from RENDER_METHODS: {sorted(undeclared)}. "
        "Add them if they are sandboxable, or rename them if they are transport.")


def test_transport_is_not_in_the_sandboxable_surface():
    """The line itself: nothing that owns a handle or a loop may be listed as
    render-half work."""
    overlap = set(TRANSPORT_METHODS) & set(BaseFrontend.RENDER_METHODS)

    assert not overlap, f"transport methods listed as sandboxable: {sorted(overlap)}"


def test_render_methods_take_a_session_key_not_a_connection():
    """A render method is addressed by *which session*, never by a live socket.

    That is what makes the half sandboxable at all: the plugin names a
    destination and the kernel owns the thing that reaches it."""
    offenders = []
    for name in BaseFrontend.RENDER_METHODS:
        method = getattr(BaseFrontend, name)
        params = list(inspect.signature(method).parameters)
        if params[:2] != ["self", "session_key"]:
            offenders.append((name, params))

    assert not offenders, (
        "render methods must be addressed by session_key, not a connection: "
        f"{offenders}")


def test_the_transport_exception_is_documented():
    """The permanent half of the split has to be justified in writing, like
    every other trusted exception."""
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[1] / "effects" / "PRIMITIVES.md").read_text(encoding="utf-8")

    assert "frontend transports" in doc


# ── the contract branches at one place ───────────────────────────────────

def test_a_legacy_frontend_renders_directly(monkeypatch):
    """The default contract calls the subclass method, exactly as before."""
    seen = []

    class _Legacy(BaseFrontend):
        name = "legacy_fe"

        def render_messages(self, session_key, messages):
            seen.append((session_key, messages))

    fe = _Legacy()
    fe._render("render_messages", "s1", ["hi"])

    assert seen == [("s1", ["hi"])]


def test_an_effects_frontend_renders_through_the_boundary():
    """An effects frontend has its render driven through the shared boundary,
    with the payload passed as data -- possible only because rendering is
    addressed by session_key rather than by a live connection."""
    calls = []

    class _Effects(BaseFrontend):
        name = "effects_fe"
        contract = "effects"

        def _render_context(self, session_key):
            return None

        def _perform_effects(self, context, params, *, method="run"):
            calls.append((method, params))
            from sandbox.driver import SandboxOutcome
            return SandboxOutcome(success=True, data="rendered")

    fe = _Effects()
    result = fe._render("render_messages", "s1", ["hi"])

    assert result == "rendered"
    assert calls == [("render_messages", {"session_key": "s1", "args": [["hi"]]})]


def test_a_failing_sandboxed_render_does_not_break_the_turn():
    """A frontend that cannot draw must not break the turn that produced the
    text -- renders are fire-and-forget by design."""

    class _Broken(BaseFrontend):
        name = "broken_fe"
        contract = "effects"

        def _render_context(self, session_key):
            return None

        def _perform_effects(self, context, params, *, method="run"):
            from sandbox.driver import SandboxOutcome
            return SandboxOutcome.failed("child died", "SandboxFailure")

    assert _Broken()._render("render_messages", "s1", ["hi"]) is None


def test_transport_methods_are_never_routed_through_the_contract():
    """start/stop stay on the trusted side: a frontend's transport is the half
    that holds the handle and owns the loop."""
    import inspect

    source = inspect.getsource(BaseFrontend._render)
    for method in TRANSPORT_METHODS:
        assert f'"{method}"' not in source
