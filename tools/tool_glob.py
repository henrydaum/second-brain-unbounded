"""glob — find files by name pattern on disk.

A pure composition over the filesystem primitives: one ``ListDir`` request
enumerates the tree (kernel-side, root-confined); the glob matching, ranking,
and truncation below are ordinary pure Python running in the sandbox. The tool
never touches the filesystem itself.
"""

import re

from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import ListDir, Respond


def _compile_glob(pattern):
    """Translate a glob into a regex over '/'-separated relative paths.

    ``*`` and ``?`` never cross a separator; a ``**`` segment matches any
    number of directories. So '*.py' matches top-level files, '**/*.py' any
    depth.
    """
    segments = [s for s in pattern.replace("\\", "/").split("/") if s]
    parts = []
    for seg in segments:
        if seg == "**":
            parts.append("(?:[^/]+/)*")
            continue
        piece = ""
        for ch in seg:
            if ch == "*":
                piece += "[^/]*"
            elif ch == "?":
                piece += "[^/]"
            else:
                piece += re.escape(ch)
        parts.append(piece + "/")
    body = "".join(parts)
    if body.endswith("/"):
        body = body[:-1]
    return re.compile("^" + body + "$", re.IGNORECASE)


class GlobTool(BaseSandboxTool):
    name = "glob"
    description = (
        "Find files by glob pattern, returned newest-first. Searches the project "
        "root by default; paths may be absolute or relative to it. Patterns: '*.py' "
        "matches top-level files only, '**/*.py' matches any depth, 'src/**/*.ts' "
        "scopes to a subtree. Skips junk dirs (.git, node_modules, __pycache__, ...). "
        "Use grep instead to search file contents."
    )
    parameters = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "description": "Glob pattern, e.g. '**/*.py' (any depth) or '*.md' (top level)."},
            "path": {"type": "string", "description": "Directory to search under. Absolute or relative to the project root. Defaults to the project root."},
            "limit": {"type": "integer", "description": "Max file paths to return. Default 100, max 500."},
        },
        "required": ["pattern"],
    }
    fill_prompt = (
        "Give a glob in `pattern`. Use '**' to match any depth ('**/*.py') or a plain "
        "'*' for a single level ('*.md'). Scope with `path` when you know the subtree."
    )
    declared_requests = ["list_dir"]
    view = "params_only"
    max_calls = 10

    def run(self, params):
        limit = max(1, min(500, int(params.get("limit", 100) or 100)))
        listing = yield ListDir(root=params.get("path", "") or "")
        if not listing.ok:
            return Respond(summary="glob failed: " + listing.error, success=False, error=listing.error)

        rx = _compile_glob(params["pattern"])
        root = listing.value["root"].replace("\\", "/").rstrip("/")
        hits = [e for e in listing.value["entries"] if rx.match(e["path"])]
        hits.sort(key=lambda e: e["mtime"], reverse=True)
        truncated = listing.value.get("truncated", False) or len(hits) > limit
        matches = [root + "/" + e["path"] for e in hits[:limit]]

        data = {"root": root, "matches": matches, "count": len(matches), "truncated": truncated}
        if not matches:
            return Respond(summary="No files matched.", data=data)
        trailer = "\n\n(results truncated)" if truncated else ""
        lines = "\n".join("- " + m for m in matches)
        return Respond(summary=str(len(matches)) + " file(s):\n" + lines + trailer, data=data)
