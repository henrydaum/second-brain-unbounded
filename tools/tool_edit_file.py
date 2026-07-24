"""edit_file — create / overwrite / replace / append / delete a UTF-8 text file.

A pure composition over the filesystem primitives. It **reads fresh inside the
run** (a same-run ReadFile, so there is no stale-read window and no session
read-gate to track), does the string work here, and yields WriteFile/DeleteFile.
Path confinement and write approval are the kernel's job: a write outside the
free drafting roots (scratch, sandbox plugins, memory) is gated through the
approval surface before it lands, and a denial returns as a normal failure.
"""

import re
from difflib import SequenceMatcher

from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import ReadFile, WriteFile, DeleteFile, Stat, Respond

NEAREST_MIN_RATIO = 0.4
NEAREST_MAX_LINES = 10_000
NEAREST_QUOTE_CAP = 1200
LINE_PREFIX_RE = re.compile(r"\s*\d+:\s")
LINE_PREFIX_HINT = (
    " Your old_text looks like it includes read_file's 'N:' line-number "
    "prefixes — strip them, or read with line_numbers=false."
)


class EditFileTool(BaseSandboxTool):
    name = "edit_file"
    description = (
        "Create, overwrite, exact-replace, append to, or delete a UTF-8 text file. "
        "For replace, old_text must match the raw file exactly — read with "
        "line_numbers=false when copying text to replace. Paths may be absolute or "
        "relative to the project root. Edits under the scratch and sandbox folders "
        "are frictionless; edits elsewhere pause for your approval."
    )
    parameters = {
        "type": "object",
        "properties": {
            "operation": {"type": "string", "enum": ["create", "overwrite", "replace", "append", "delete"], "description": "File operation to perform."},
            "path": {"type": "string", "description": "Target file path, absolute or relative to the project root."},
            "content": {"type": "string", "description": "Text for create, overwrite, or append."},
            "old_text": {"type": "string", "description": "Exact text to replace."},
            "new_text": {"type": "string", "description": "Replacement text."},
            "replace_all": {"type": "boolean", "description": "Replace every occurrence instead of requiring exactly one match."},
            "justification": {"type": "string", "description": "Short plain-English reason for the edit, shown in the approval dialog for non-scratch paths."},
        },
        "required": ["operation", "path", "justification"],
    }
    fill_prompt = (
        "Pick the `operation`, give the `path`, and a one-line `justification`. For "
        "replace, `old_text` must match the raw file exactly (read with "
        "line_numbers=false first). Use `replace_all` when the text repeats."
    )
    declared_requests = ["read_file", "write_file", "delete_file", "stat"]
    view = "params_only"
    max_calls = 20
    background_safe = False

    def run(self, params):
        op = (params.get("operation") or "").strip().lower()
        path = (params.get("path") or "").strip()
        if not path:
            return Respond(summary="edit_file failed: path is required.", success=False, error="path required")
        if not (params.get("justification") or "").strip():
            return Respond(summary="edit_file failed: a justification is required.", success=False, error="justification required")

        if op == "delete":
            info = yield Stat(path=path)
            if not (info.ok and info.value.get("exists")):
                return Respond(summary=f"edit_file failed: file not found: {path}", success=False, error="not found")
            res = yield DeleteFile(path=path)
            return self._result(res, op, path, "Deleted")

        if op in ("create", "overwrite", "append"):
            content = params.get("content")
            if content is None:
                return Respond(summary="edit_file failed: content is required for create/overwrite/append.", success=False, error="content required")
            info = yield Stat(path=path)
            exists = bool(info.ok and info.value.get("exists"))
            if op == "create" and exists:
                return Respond(summary=f"edit_file failed: file already exists: {path}", success=False, error="exists")
            body = content
            if op == "append" and exists:
                prior = yield ReadFile(path=path)
                if prior.ok:
                    body = prior.value + content
            res = yield WriteFile(path=path, content=body)
            verb = {"create": "Created", "overwrite": "Overwrote", "append": "Appended to"}[op]
            return self._result(res, op, path, verb)

        if op == "replace":
            old, new = params.get("old_text"), params.get("new_text")
            if not old:
                return Respond(summary="edit_file failed: old_text is required for replace.", success=False, error="old_text required")
            if new is None:
                return Respond(summary="edit_file failed: new_text is required for replace.", success=False, error="new_text required")
            cur = yield ReadFile(path=path)
            if not cur.ok:
                return Respond(summary=f"edit_file failed: {cur.error}", success=False, error=cur.error)
            text = cur.value
            count = text.count(old)
            if count == 0:
                return Respond(summary="edit_file: " + _not_found_error(text, old), success=False, error="old_text not found")
            if count > 1 and not params.get("replace_all"):
                return Respond(
                    summary=f"edit_file: old_text appears {count} times (lines {_occurrence_lines(text, old)}); "
                            "pass replace_all=true or make it unique.",
                    success=False, error="ambiguous match")
            n = count if params.get("replace_all") else 1
            replaced = text.replace(old, new, -1 if params.get("replace_all") else 1)
            res = yield WriteFile(path=path, content=replaced)
            return self._result(res, op, path, f"Replaced {n} occurrence(s) in")

        return Respond(summary="edit_file failed: operation must be create, overwrite, replace, append, or delete.",
                       success=False, error="bad operation")

    @staticmethod
    def _result(res, op, path, verb):
        """Map a write/delete fulfilment onto the tool's Respond."""
        if not res.ok:
            if res.denied:
                return Respond(
                    summary=f"edit_file: {op} denied by user. STOP — do not retry; ask what to do instead.",
                    success=False, error=res.error or "denied")
            return Respond(summary=f"edit_file failed: {res.error}", success=False, error=res.error)
        return Respond(summary=f"{verb} {path}.", data={"path": path, "operation": op})


def _not_found_error(text: str, old: str) -> str:
    """Self-correcting no-match error: quote the closest region + flag N: prefixes."""
    msg = "old_text was not found."
    old_lines = old.splitlines()
    numbered = sum(1 for l in old_lines if LINE_PREFIX_RE.match(l))
    if numbered >= 2 and numbered * 2 >= len(old_lines):
        msg += LINE_PREFIX_HINT
    lines = text.splitlines()
    n = len(old_lines)
    if not n or len(lines) > NEAREST_MAX_LINES:
        return msg
    sm = SequenceMatcher(None, "", old, autojunk=False)
    best_ratio, best_at = 0.0, -1
    for i in range(max(1, len(lines) - n + 1)):
        window = "\n".join(lines[i:i + n])
        sm.set_seq1(window)
        if sm.real_quick_ratio() <= best_ratio or sm.quick_ratio() <= best_ratio:
            continue
        ratio = sm.ratio()
        if ratio > best_ratio:
            best_ratio, best_at = ratio, i
    if best_ratio >= NEAREST_MIN_RATIO and best_at >= 0:
        quote = "\n".join(lines[best_at:best_at + n])[:NEAREST_QUOTE_CAP]
        msg += (f" Closest match (lines {best_at + 1}-{min(best_at + n, len(lines))}):\n{quote}")
    return msg


def _occurrence_lines(text: str, old: str, cap: int = 10) -> str:
    """Line numbers of the first ``cap`` occurrences, comma-joined."""
    out, start = [], 0
    while len(out) < cap:
        idx = text.find(old, start)
        if idx == -1:
            break
        out.append(str(text.count("\n", 0, idx) + 1))
        start = idx + 1
    return ", ".join(out)
