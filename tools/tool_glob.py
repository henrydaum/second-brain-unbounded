"""glob — find files by name pattern on disk.

A pure composition over the filesystem primitives: one ``ListDir`` request
enumerates the tree (kernel-side, root-confined); the glob matching, ranking,
and truncation below are ordinary pure Python running in the sandbox (shared
with grep and every future filesystem tool via ``sandbox_kit``). The tool never
touches the filesystem itself.
"""

import sandbox_kit as kit
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import ListDir, Respond


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
        limit = kit.clamp(params.get("limit"), 1, 500, 100)
        listing = yield ListDir(root=params.get("path", "") or "")
        if not listing.ok:
            return Respond(summary="glob failed: " + listing.error, success=False, error=listing.error)

        rx = kit.compile_glob(params["pattern"])
        root = listing.value["root"].replace("\\", "/").rstrip("/")
        hits = kit.newest_first(e for e in listing.value["entries"] if rx.match(e["path"]))
        truncated = listing.value.get("truncated", False) or len(hits) > limit
        matches = [kit.join_root(root, e["path"]) for e in hits[:limit]]

        data = {"root": root, "matches": matches, "count": len(matches), "truncated": truncated}
        if not matches:
            return Respond(summary="No files matched.", data=data)
        trailer = "\n\n(results truncated)" if truncated else ""
        return Respond(summary=str(len(matches)) + " file(s):\n" + kit.bullet_list(matches) + trailer, data=data)
