"""grep — regex search over file contents on disk.

A pure composition over the filesystem primitives: one ``ListDir`` request
enumerates candidates, batched ``ReadFiles`` requests fetch their text, and the
regex matching, glob filtering, ranking, and formatting below are ordinary pure
Python running in the sandbox. The tool never touches the filesystem itself —
the resumable request loop is doing exactly what it was designed for.
"""

import re

import sandbox_kit as kit
from plugins.BaseTool import BaseTool
from effects.vocabulary import ListDir, ReadFiles, Respond

MAX_FILE_BYTES = 2_000_000
BATCH = 100


class GrepTool(BaseTool):
    contract = "effects"
    name = "grep"
    description = (
        "Search file contents on disk with a Python regular expression (re syntax, not PCRE). "
        "Searches the project root by default; paths may be absolute or relative to it. "
        "Filter files with 'glob' ('*.py' = top level, '**/*.py' = any depth). Skips binary "
        "and very large files and junk dirs (.git, node_modules, __pycache__, ...). Reads "
        "live files on disk right now, so it sees uncommitted and unindexed content. Give a "
        "Python `re` regex in `pattern`. Narrow the search with `path` and/or `glob` when you "
        "can. Choose `output_mode`: files_with_matches to locate files, content to see "
        "matching lines, count to tally hits."
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
    declared_requests = ["list_dir", "read_files"]
    view = "params_only"
    max_calls = 10

    def run(self, params):
        limit = kit.clamp(params.get("limit"), 1, 500, 100)
        mode = params.get("output_mode", "files_with_matches") or "files_with_matches"
        context = kit.clamp(params.get("context_lines"), 0, 10, 0)
        multiline = bool(params.get("multiline", False))

        flags = re.IGNORECASE if params.get("case_insensitive") else 0
        if multiline:
            flags |= re.DOTALL | re.MULTILINE
        try:
            rx = re.compile(params["pattern"], flags)
        except re.error as e:
            msg = "invalid regex: " + str(e)
            return Respond(summary="grep failed: " + msg, success=False, error=msg)

        listing = yield ListDir(root=params.get("path", "") or "")
        if not listing.ok:
            return Respond(summary="grep failed: " + listing.error, success=False, error=listing.error)
        root = listing.value["root"].replace("\\", "/").rstrip("/")
        entries = [e for e in listing.value["entries"] if e["size"] <= MAX_FILE_BYTES]
        if params.get("glob"):
            grx = kit.compile_glob(params["glob"])
            entries = [e for e in entries if grx.match(e["path"])]
        entries = kit.newest_first(entries)
        truncated = listing.value.get("truncated", False)

        files_out = []
        content_out = []
        count_out = []

        def full():
            """True once the requested output mode has hit its limit."""
            return len(files_out) >= limit or len(content_out) >= limit or len(count_out) >= limit

        for start in range(0, len(entries), BATCH):
            if full():
                truncated = True
                break
            batch = entries[start:start + BATCH]
            reads = yield ReadFiles(paths=[kit.join_root(root, e["path"]) for e in batch])
            for e, f in zip(batch, reads.value["files"]):
                if full():
                    truncated = True
                    break
                if "error" in f:
                    continue  # binary / unreadable — skip, like classic grep
                self._match_one(e["path"], f["text"], rx, mode, context, multiline,
                                limit, files_out, content_out, count_out)

        if mode == "content":
            data = {"root": root, "mode": mode, "matches": content_out[:limit], "truncated": truncated}
        elif mode == "count":
            data = {"root": root, "mode": mode, "counts": count_out[:limit], "truncated": truncated}
        else:
            data = {"root": root, "mode": mode, "files": files_out[:limit], "truncated": truncated}
        return Respond(summary=_summarize(data), data=data)

    def _match_one(self, rel, text, rx, mode, context, multiline,
                   limit, files_out, content_out, count_out):
        """Pure per-file matching; appends into the output accumulators."""
        lines = text.splitlines()
        if multiline:
            hits = list(rx.finditer(text))
            if not hits:
                return
            if mode == "files_with_matches":
                files_out.append(rel)
            elif mode == "count":
                count_out.append({"file": rel, "count": len(hits)})
            else:
                for m in hits:
                    lineno = text.count("\n", 0, m.start()) + 1
                    line = lines[lineno - 1] if lineno - 1 < len(lines) else ""
                    content_out.append(rel + ":" + str(lineno) + ": " + line)
                    if len(content_out) >= limit:
                        return
            return

        matched = [i for i, line in enumerate(lines) if rx.search(line)]
        if not matched:
            return
        if mode == "files_with_matches":
            files_out.append(rel)
        elif mode == "count":
            count_out.append({"file": rel, "count": len(matched)})
        else:
            for idx in matched:
                if context:
                    lo = max(0, idx - context)
                    hi = min(len(lines), idx + context + 1)
                    for j in range(lo, hi):
                        sep = ":" if j == idx else "-"
                        content_out.append(rel + ":" + str(j + 1) + sep + " " + lines[j])
                else:
                    content_out.append(rel + ":" + str(idx + 1) + ": " + lines[idx])
                if len(content_out) >= limit:
                    return


def _summarize(data):
    """Render the grep result as compact markdown for the model."""
    trailer = "\n\n(results truncated)" if data.get("truncated") else ""
    if data["mode"] == "content":
        matches = data.get("matches", [])
        if not matches:
            return "No matches."
        return str(len(matches)) + " matching line(s):\n" + "\n".join(matches) + trailer
    if data["mode"] == "count":
        counts = data.get("counts", [])
        if not counts:
            return "No matches."
        rows = kit.bullet_list(c["file"] + ": " + str(c["count"]) for c in counts)
        return "Match counts:\n" + rows + trailer
    files = data.get("files", [])
    if not files:
        return "No matches."
    return str(len(files)) + " file(s) with matches:\n" + kit.bullet_list(files) + trailer
