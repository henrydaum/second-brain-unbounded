"""Deprecated compatibility shim — sandboxed tools are now ordinary ``BaseTool``s.

There is deliberately **one base class per plugin family**. A tool's execution
mode (in-process vs subprocess) is decided by *provenance* at call time, not by
which class it inherits from — see ``BaseTool.trusted`` and
``plugins.helpers.plugin_paths.is_trusted``.

The reason is not tidiness. If the contract differed by mode, changing a
plugin's trust would require rewriting it, and demotion would be expensive
enough that it would never happen. One contract makes trust a flag.

Writing a new tool: subclass :class:`~plugins.BaseTool.BaseTool` and set
``contract = "effects"``. Everything that used to live here — ``declared_requests``,
``view``/``view_k``, ``timeout_s``/``memory_mb``/``cpu_seconds``, the derived
``danger_tier`` — is on ``BaseTool`` now.

This shim exists so tools already written against ``BaseSandboxTool`` (notably
the store tree) keep working unchanged during the migration. It is scheduled for
deletion once those are converted.
"""

from __future__ import annotations

from plugins.BaseTool import BaseTool


class BaseSandboxTool(BaseTool):
    """Deprecated alias: a ``BaseTool`` with ``contract = "effects"`` preset.

    Subclasses keep their existing generator ``run(self, params)`` body and need
    no changes; discovery registers them exactly like any other tool.
    """

    contract = "effects"
