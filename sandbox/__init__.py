"""The tool sandbox: pure tools as generators in subprocess isolation.

A sandboxed tool is a generator that yields typed effect requests
(``effects.vocabulary``) and receives their fulfilments back, ending by
returning (or yielding) a ``Respond``. It runs in a child ``python -I`` process
with AST-validated source, a restricted import gate, and no ambient db, socket,
or filesystem handle — its only wire to the world is the request stream, which
the parent fulfils through ``effects.interpreter``.

- ``sandbox.validate`` — AST validation + import allowlist (rejects code before
  it ever runs).
- ``sandbox.protocol`` — the JSON-lines wire format spoken over the pipe.
- ``sandbox.entry``    — the child process: exec, locate the tool, drive its
  generator, speak the protocol.
- ``sandbox.runner``   — the parent boss: spawn the child, fulfil each yielded
  request, enforce timeout, return a ``ToolResult``.
"""

from sandbox.validate import SandboxValidationError, assert_valid
from sandbox.runner import SandboxRunError, run_sandbox_tool

__all__ = [
    "SandboxValidationError",
    "assert_valid",
    "SandboxRunError",
    "run_sandbox_tool",
]
