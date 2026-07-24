"""Kernel-side filesystem *resource* access — the engine behind ListDir /
ReadFiles / Stat.

Deliberately algorithm-free: this module enumerates and reads, nothing more.
Glob matching, regex search, ranking, and every future file-shaped cleverness
are pure code that lives in sandboxed tools, composed on top of these
primitives. Keeping the kernel side to resource access is what keeps the
primitive set closed (the grep lesson: verbs creep, resources don't).

All walks are confined to the caller's allowed read roots, skip well-known junk
directories, and never follow symlinks / Windows junctions, so a cycle or an
escape cannot occur. Pure stdlib.
"""

from __future__ import annotations

import os
import stat as stat_mod
from pathlib import Path

IGNORED_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__",
    ".venv", "venv", ".tox", ".eggs",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".cache",
    "dist", "build", ".idea",
}

MAX_FILE_BYTES = 2_000_000    # per-file read cap
MAX_SCAN_FILES = 20_000       # enumeration bound per walk
MAX_BATCH_FILES = 500         # files per ReadFiles request
MAX_BATCH_BYTES = 8_000_000   # total text per ReadFiles request


def _default_root(allowed_roots: list[Path] | None) -> Path:
    """The root a walk starts from when the caller names none."""
    if allowed_roots:
        return Path(allowed_roots[0]).resolve()
    return Path.cwd().resolve()


def resolve_root(raw: str | None, allowed_roots: list[Path] | None) -> tuple[Path | None, str | None]:
    """Resolve a caller-supplied path and confine it to the allowed roots.

    Returns ``(path, None)`` on success or ``(None, error)`` when the path
    escapes every allowed root. ``allowed_roots=None`` means "trusted, allow
    anywhere" (tests) — the path is still resolved but never rejected.
    """
    raw = (raw or "").strip()
    default = _default_root(allowed_roots)
    p = Path(raw).expanduser() if raw else default
    p = (p if p.is_absolute() else default / p).resolve()
    if not allowed_roots:
        return p, None
    roots = [Path(r).expanduser().resolve() for r in allowed_roots]
    if any(p == root or root in p.parents for root in roots):
        return p, None
    return None, f"path is outside the allowed read roots: {p}"


def _is_link(entry_path: str) -> bool:
    """True for symlinks and Windows reparse points (junctions)."""
    try:
        st = os.lstat(entry_path)
    except OSError:
        return True  # unreadable — treat as skippable
    if stat_mod.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    reparse = getattr(stat_mod, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attrs & reparse)


def is_binary(path: Path) -> bool:
    """Null-byte sniff on the first KB; unreadable files count as binary."""
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(1024)
    except OSError:
        return True


# ── primitive entry points (what the interpreter calls) ──────────────────

def list_dir(root: str | None, allowed_roots: list[Path] | None,
             recursive: bool = True) -> dict:
    """Enumerate files under ``root``: relative path + size + mtime per entry.

    Junk dirs pruned, links skipped, bounded by ``MAX_SCAN_FILES`` (sets
    ``truncated``). Sorting/filtering is the caller's business.
    """
    root_path, err = resolve_root(root, allowed_roots)
    if err:
        return {"error": err}
    if not root_path.is_dir():
        return {"error": f"not a directory: {root_path}"}

    entries: list[dict] = []
    truncated = False

    def _add(full: str) -> bool:
        """Append one file entry; return False when the scan cap is hit."""
        try:
            st = os.stat(full)
        except OSError:
            return True
        rel = Path(full).relative_to(root_path).as_posix()
        entries.append({"path": rel, "size": st.st_size, "mtime": st.st_mtime})
        return len(entries) < MAX_SCAN_FILES

    if recursive:
        for dirpath, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=False):
            dirnames[:] = [
                d for d in dirnames
                if d not in IGNORED_DIRS and not _is_link(os.path.join(dirpath, d))
            ]
            for name in filenames:
                full = os.path.join(dirpath, name)
                if _is_link(full):
                    continue
                if not _add(full):
                    truncated = True
                    break
            if truncated:
                break
    else:
        try:
            with os.scandir(root_path) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False) and not _is_link(entry.path):
                        if not _add(entry.path):
                            truncated = True
                            break
        except OSError as e:
            return {"error": str(e)}

    return {"root": str(root_path), "entries": entries, "truncated": truncated}


def read_files(paths: list[str], allowed_roots: list[Path] | None,
               max_bytes_per_file: int = MAX_FILE_BYTES) -> dict:
    """Read up to ``MAX_BATCH_FILES`` files in one call.

    Per-file outcomes, never batch failure: each entry is
    ``{path, text}`` or ``{path, error}`` (confinement, binary, oversize,
    unreadable). ``truncated`` marks a batch cut short by the file-count or
    total-bytes cap.
    """
    per_file_cap = min(int(max_bytes_per_file or MAX_FILE_BYTES), MAX_FILE_BYTES)
    out: list[dict] = []
    total = 0
    truncated = len(paths) > MAX_BATCH_FILES
    for raw in paths[:MAX_BATCH_FILES]:
        if total >= MAX_BATCH_BYTES:
            truncated = True
            break
        p, err = resolve_root(raw, allowed_roots)
        if err:
            out.append({"path": raw, "error": err})
            continue
        try:
            if p.stat().st_size > per_file_cap:
                out.append({"path": raw, "error": f"file exceeds {per_file_cap} bytes"})
                continue
            if is_binary(p):
                out.append({"path": raw, "error": "binary file"})
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            out.append({"path": raw, "error": str(e)})
            continue
        total += len(text)
        out.append({"path": raw, "text": text})
    return {"files": out, "truncated": truncated}


def stat_path(raw: str, allowed_roots: list[Path] | None) -> dict:
    """Metadata for one path: existence, kind, size, mtime."""
    p, err = resolve_root(raw, allowed_roots)
    if err:
        return {"error": err}
    if not p.exists():
        return {"path": str(p), "exists": False}
    try:
        st = p.stat()
    except OSError as e:
        return {"error": str(e)}
    return {
        "path": str(p),
        "exists": True,
        "is_dir": p.is_dir(),
        "size": st.st_size,
        "mtime": st.st_mtime,
    }
