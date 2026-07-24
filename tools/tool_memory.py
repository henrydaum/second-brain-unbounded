"""memory — read, save, append, or forget durable per-topic memory files.

Memory is a folder of markdown topic files plus a ``MEMORY.md`` index (the
kernel inlines only the index into the prompt; this tool reads and writes the
bodies). The memory folder is resolved via ``ReadContext("paths")`` and is a
*free* write root, so these writes need no approval — they are hard-confined to
the user's memory folder and nothing else. Topic-name validation mirrors the
kernel's ``memory_paths.topic_path`` (which can't be imported in-sandbox).
"""

import re

import sandbox_kit as kit
from plugins.BaseSandboxTool import BaseSandboxTool
from effects.vocabulary import ReadContext, ReadFile, WriteFile, DeleteFile, ListDir, Respond

INDEX_FILENAME = "MEMORY.md"
MAX_READ_CHARS = 20_000
_TOPIC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]*$")


class MemoryTool(BaseSandboxTool):
    name = "memory"
    description = (
        "Read, save, append, or forget durable memory topics. Each topic is a "
        "markdown file; the MEMORY.md index in your system prompt maps topics. "
        "Read a topic before answering from it — the index is a map, not the content."
    )
    parameters = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["read", "save", "append", "forget"], "description": "read: return a topic. save: create/overwrite. append: add to a topic. forget: delete a topic and its index line."},
            "topic": {"type": "string", "description": "Topic name (becomes <topic>.md). Letters, digits, dots, dashes, underscores, spaces."},
            "content": {"type": "string", "description": "Markdown body for save/append."},
            "description": {"type": "string", "description": "One-line index hook for save/append — what this topic holds and when to read it."},
        },
        "required": ["action", "topic"],
    }
    fill_prompt = (
        "Choose the `action` and `topic`. For save/append give `content` and a "
        "one-line `description` for the index. Read a topic before answering from it."
    )
    declared_requests = ["read_file", "write_file", "delete_file", "list_dir"]
    view = "params_only"
    max_calls = 10

    def run(self, params):
        action = (params.get("action") or "").strip().lower()
        stem, err = _valid_stem(params.get("topic"))
        if err:
            return Respond(summary="memory failed: " + err, success=False, error=err)

        paths = yield ReadContext(view="paths")
        root = (paths.value or {}).get("memory_root")
        if not root:
            return Respond(summary="memory failed: the memory folder is unavailable here.",
                           success=False, error="no memory root")
        topic_file = kit.join_root(root, stem + ".md")
        index_file = kit.join_root(root, INDEX_FILENAME)

        if action == "read":
            res = yield ReadFile(path=topic_file)
            if not res.ok:
                listing = yield ListDir(root=root, recursive=False)
                names = sorted(e["path"][:-3] for e in (listing.value or {}).get("entries", [])
                               if e["path"].endswith(".md") and e["path"] != INDEX_FILENAME)
                return Respond(summary=f"memory: no topic '{stem}'. Topics: {', '.join(names) or '(none)'}",
                               success=False, error="no such topic")
            text, _ = kit.truncate_chars(res.value, MAX_READ_CHARS)
            return Respond(summary=text, data={"topic": stem})

        if action in ("save", "append"):
            content = (params.get("content") or "").strip()
            if not content:
                return Respond(summary=f"memory failed: '{action}' needs non-empty content.",
                               success=False, error="empty content")
            body = content
            if action == "append":
                prior = yield ReadFile(path=topic_file)
                if prior.ok and prior.value.strip():
                    body = prior.value.rstrip() + "\n\n" + content
            w = yield WriteFile(path=topic_file, content=body.rstrip() + "\n")
            if not w.ok:
                return Respond(summary="memory failed: " + w.error, success=False, error=w.error)
            idx = yield ReadFile(path=index_file)
            lines = [l for l in (idx.value.splitlines() if idx.ok else []) if l.strip()]
            lines = _upsert_index(lines, stem, (params.get("description") or "").strip(), content)
            yield WriteFile(path=index_file, content=("\n".join(lines).rstrip() + "\n") if lines else "")
            return Respond(summary=f"Memory topic '{stem}' {'appended' if action == 'append' else 'saved'}.",
                           data={"topic": stem})

        if action == "forget":
            d = yield DeleteFile(path=topic_file)
            existed = bool(d.ok and (d.value or {}).get("existed"))
            idx = yield ReadFile(path=index_file)
            if idx.ok:
                prefix = _entry_prefix(stem)
                kept = [l for l in idx.value.splitlines() if l.strip() and not l.startswith(prefix)]
                yield WriteFile(path=index_file, content=("\n".join(kept).rstrip() + "\n") if kept else "")
            return Respond(
                summary=f"Memory topic '{stem}' {'forgotten' if existed else 'did not exist (index cleaned)'}.",
                data={"topic": stem})

        return Respond(summary=f"memory failed: unknown action {action!r}. Use read, save, append, or forget.",
                       success=False, error="bad action")


def _valid_stem(topic):
    """(stem, None) for a valid topic name, else (None, error). Mirrors
    memory_paths.topic_path's rules."""
    name = (topic or "").strip()
    if name.lower().endswith(".md"):
        name = name[:-3]
    if not name or not _TOPIC_RE.match(name) or name.upper() == "MEMORY":
        return None, f"invalid memory topic name: {topic!r}"
    return name, None


def _entry_prefix(topic: str) -> str:
    return f"- [{topic}]({topic}.md)"


def _upsert_index(lines, topic, description, content):
    """Create or update the topic's one-line index entry (pure list transform).

    Without an explicit description a new entry falls back to the first content
    line; an existing entry's description is left alone."""
    prefix = _entry_prefix(topic)
    existing = next((i for i, l in enumerate(lines) if l.startswith(prefix)), None)
    if existing is not None and not description:
        return lines
    hook = (description or (content.splitlines()[0].strip() if content else ""))[:120]
    entry = f"{prefix} - {hook}" if hook else prefix
    if existing is not None:
        lines[existing] = entry
    else:
        lines.append(entry)
    return lines
