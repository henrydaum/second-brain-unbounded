"""The JSON-lines wire protocol spoken between the sandbox parent and child.

One JSON object per line, in both directions. Unlike Art's one-shot job (write a
PNG and exit), a tool run is a *conversation*: the child yields requests and
blocks for their fulfilments until it produces a final result.

Child → parent, one of:
- ``{"yield": <request-wire>}``  — the tool yielded an effect request.
- ``{"final": <respond-wire>}``  — the tool finished (a Respond payload).
- ``{"error": <diagnostic>}``    — the tool raised; run failed.

Parent → child (only in reply to a ``yield``):
- ``{"resume": <effect-result-wire>}`` — the fulfilment to send back in.

Keeping this a tiny module with no kernel imports means both the trusted parent
and the restricted child can import it without widening the child's surface.
"""

from __future__ import annotations

import base64
import json
from typing import Any


def _default(obj: Any) -> Any:
    """Serialize values JSON can't handle natively. ``bytes`` are wrapped as
    ``{"__b64__": ...}`` so binary columns (e.g. embedding BLOBs from a QueryDb)
    round-trip losslessly to the child; anything else falls back to ``str`` (the
    prior best-effort behaviour)."""
    if isinstance(obj, (bytes, bytearray)):
        return {"__b64__": base64.b64encode(bytes(obj)).decode("ascii")}
    return str(obj)


def _object_hook(d: dict) -> Any:
    """Restore a ``{"__b64__": ...}`` wrapper back to ``bytes``."""
    if len(d) == 1 and "__b64__" in d:
        return base64.b64decode(d["__b64__"])
    return d


def write_message(stream, message: dict[str, Any]) -> None:
    """Write one framed JSON message and flush."""
    stream.write(json.dumps(message, default=_default))
    stream.write("\n")
    stream.flush()


def read_message(stream) -> dict[str, Any] | None:
    """Read one framed JSON message, or ``None`` at EOF."""
    line = stream.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return {}
    return json.loads(line, object_hook=_object_hook)
