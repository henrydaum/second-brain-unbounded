"""grep — regex search over file contents on disk.

A sandboxed tool: pure code that yields a single ``Grep`` effect request and
shapes the result. The kernel fulfils the request read-only, confined to the
allowed read roots — the tool itself never touches the filesystem.
"""

from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import Grep, Respond


class GrepTool(BaseSandboxTool):
    name = "grep"
    description = (
        "Search file contents on disk with a Python regular expression (re syntax, "
        "not PCRE). Searches the project root by default; paths may be absolute or "
        "relative to it. Filter files with 'glob' ('*.py' = top level, '**/*.py' = "
        "any depth). Skips binary and very large files and junk dirs (.git, "
        "node_modules, __pycache__, ...). Reads live files on disk right now, so it "
        "sees uncommitted and unindexed content."
    )
    parameters = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "description": "Python re regular expression to search for."},
            "path": {"type": "string", "description": "File or directory to search. Absolute or relative to the project root. Defaults to the project root."},
            "glob": {"type": "string", "description": "Glob filter for files, e.g. '*.py' (top level) or '**/*.py' (any depth)."},
            "output_mode": {"type": "string", "enum": ["files_with_matches", "content", "count"], "description": "files_with_matches (default): matching file paths. content: matching lines with line numbers. count: match counts per file."},
            "case_insensitive": {"type": "boolean", "description": "Case-insensitive matching. Default false."},
            "context_lines": {"type": "integer", "description": "Lines of context around each match (content mode only, max 10). Default 0."},
            "multiline": {"type": "boolean", "description": "Let the pattern span lines ('.' matches newlines too). Default false."},
            "limit": {"type": "integer", "description": "Max results (files, lines, or count rows). Default 100, max 500."},
        },
        "required": ["pattern"],
    }
    fill_prompt = (
        "Give a Python `re` regex in `pattern`. Narrow the search with `path` and/or "
        "`glob` when you can. Choose `output_mode`: files_with_matches to locate files, "
        "content to see matching lines, count to tally hits."
    )
    declared_requests = ["grep"]
    view = "params_only"
    max_calls = 10

    def run(self, params):
        res = yield Grep(
            pattern=params["pattern"],
            root=params.get("path", "") or "",
            glob=params.get("glob", "") or "",
            output_mode=params.get("output_mode", "files_with_matches") or "files_with_matches",
            case_insensitive=bool(params.get("case_insensitive", False)),
            context_lines=int(params.get("context_lines", 0) or 0),
            multiline=bool(params.get("multiline", False)),
            limit=max(1, min(500, int(params.get("limit", 100) or 100))),
        )
        if not res.ok:
            return Respond(summary=f"grep failed: {res.error}", success=False, error=res.error)
        return Respond(summary=_summarize(res.value), data=res.value)


def _summarize(data):
    """Render the grep result as compact markdown for the model."""
    mode = data.get("mode")
    trailer = "\n\n(results truncated)" if data.get("truncated") else ""
    if mode == "content":
        lines = data.get("matches", [])
        if not lines:
            return "No matches."
        return f"{len(lines)} matching line(s):\n" + "\n".join(lines) + trailer
    if mode == "count":
        counts = data.get("counts", [])
        if not counts:
            return "No matches."
        rows = "\n".join(f"- {c['file']}: {c['count']}" for c in counts)
        return f"Match counts:\n{rows}" + trailer
    files = data.get("files", [])
    if not files:
        return "No matches."
    return f"{len(files)} file(s) with matches:\n" + "\n".join(f"- {f}" for f in files) + trailer
