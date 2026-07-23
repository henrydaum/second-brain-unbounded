"""glob — find files by name pattern on disk.

A sandboxed tool: pure code that yields a single ``Glob`` effect request and
shapes the result. The kernel walks the disk read-only, confined to the allowed
read roots — the tool itself never touches the filesystem.
"""

from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import Glob, Respond


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
    declared_requests = ["glob"]
    view = "params_only"
    max_calls = 10

    def run(self, params):
        res = yield Glob(
            pattern=params["pattern"],
            root=params.get("path", "") or "",
            limit=max(1, min(500, int(params.get("limit", 100) or 100))),
        )
        if not res.ok:
            return Respond(summary=f"glob failed: {res.error}", success=False, error=res.error)
        data = res.value
        matches = data.get("matches", [])
        if not matches:
            return Respond(summary="No files matched.", data=data)
        trailer = "\n\n(results truncated)" if data.get("truncated") else ""
        summary = f"{len(matches)} file(s):\n" + "\n".join(f"- {m}" for m in matches) + trailer
        return Respond(summary=summary, data=data)
