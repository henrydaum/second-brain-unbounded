"""read_file — read a text file by path, with line windowing and a char cap.

A pure composition: one ``ReadFile`` request fetches the bytes (root-confined,
kernel-side); the windowing, line-numbering, ``.log`` reversal, and truncation
below are ordinary pure Python (``sandbox_kit`` for the shared parts). There is
no session read-gate — edit_file reads fresh inside its own run, so nothing here
needs tracking.
"""

import sandbox_kit as kit
from plugins.BaseTool import BaseTool
from effects.vocabulary import ReadFile, Respond

MAX_CHARS = 20_000
_BIG = 1_000_000_000


class ReadFileTool(BaseTool):
    contract = "effects"
    name = "read_file"
    description = (
        "Read a text file by path. Use this when you need the exact contents of source code, "
        "templates, docs, or sandbox plugins. Paths may be absolute or relative to the "
        "project root. Output is line-windowed (offset/limit) and capped at ~20k chars; .log "
        "files are read newest-first. Give the file `path`. Page big files with "
        "`offset`/`limit`. Pass `line_numbers=false` when you'll copy the text into "
        "edit_file's old_text."
    )
    parameters = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path to read, absolute or relative to the project root."},
            "offset": {"type": "integer", "description": "1-indexed line to start from. Default 1. For .log files this counts from the newest line."},
            "limit": {"type": "integer", "description": "Maximum number of lines to return. Output is also capped at ~20k chars."},
            "line_numbers": {"type": "boolean", "description": "Include 1-indexed line numbers. Defaults to true; pass false when you need raw text for exact replacement."},
        },
        "required": ["path"],
    }
    declared_requests = ["read_file"]
    view = "params_only"
    max_calls = 10

    def run(self, params):
        raw = (params.get("path") or "").strip()
        if not raw:
            return Respond(summary="read_file failed: no path provided.", success=False, error="no path provided")
        offset = kit.clamp(params.get("offset"), 1, _BIG, 1)

        result = yield ReadFile(path=raw)
        if not result.ok:
            return Respond(summary="read_file failed: " + result.error, success=False, error=result.error)

        lines = (result.value or "").splitlines()
        if raw.lower().endswith(".log"):
            lines = list(reversed(lines))  # logs newest-first
        total = len(lines)
        start = min(offset - 1, total)
        limit_raw = params.get("limit")
        end = total if limit_raw is None else min(start + kit.clamp(limit_raw, 1, _BIG, 1), total)

        window = lines[start:end]
        if params.get("line_numbers", True):
            window = [f"{i}: {line}" for i, line in enumerate(window, start + 1)]
        body, char_truncated = kit.truncate_chars("\n".join(window), MAX_CHARS)

        notes = []
        if start > 0:
            notes.append(f"showing lines {start + 1}-{end} of {total}")
        elif end < total:
            notes.append(f"showing lines 1-{end} of {total}")
        if char_truncated:
            notes.append(f"output capped at {MAX_CHARS} chars — pass offset/limit to page further")
        if notes:
            body += "\n\n... (" + "; ".join(notes) + ")"
        return Respond(summary=body, data={"path": raw, "total_lines": total})
