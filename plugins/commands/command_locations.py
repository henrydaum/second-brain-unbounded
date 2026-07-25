"""Slash command plugin for `/locations`."""

from plugins.BaseCommand import BaseCommand


class LocationsCommand(BaseCommand):
    """Slash-command handler for `/locations`.

    Was importing ``paths`` directly for ROOT_DIR / DATA_DIR / SANDBOX_PLUGINS
    and walking them with ``Path.iterdir``. Both halves now cross the boundary:
    the locations arrive as the ambient ``paths`` view, the listings as
    ``ListDir``. So the confinement policy applies to ``/locations`` like
    anything else — it can only show directories the run may read.
    """
    name = "locations"
    description = "Show project and plugin directories"
    category = "System"

    contract = "effects"
    declared_requests = ["read_context", "list_dir"]

    # Which entries of the ambient path map each choice shows. Names, not paths:
    # the plugin never learns where these actually live.
    KINDS = {
        "root": ("Project root", "root", "Data directory", "data"),
        "sandbox": ("Sandbox plugins", "scratch", "Data directory", "data"),
        "memory": ("Memory", "memory_root", "Data directory", "data"),
    }

    def form(self, _params):
        """Offer the location maps."""
        return []
        yield  # noqa: unreachable — marks this a generator for the contract

    def run(self, params):
        """Execute `/locations` for the active session."""
        from effects.vocabulary import ReadContext, Respond

        known = (yield ReadContext(view="paths")).value or {}
        left_label, left_key, right_label, right_key = self.KINDS.get(
            params.get("kind") or "root", self.KINDS["root"])

        left = yield from _section(left_label, known.get(left_key, ""))
        right = yield from _section(right_label, known.get(right_key, ""))
        return Respond(data=f"{left}\n\n{right}")


def _section(label: str, path: str):
    """Render one labelled, fenced top-level listing.

    Fenced because rich renderers collapse the single newlines of a bare
    listing.

    ``ListDir`` enumerates *files*, so a non-recursive call would omit
    directories entirely — which is most of what this command exists to show.
    Taking the first segment of each recursive entry recovers them. The walk is
    capped kernel-side, so a large data directory costs a bounded scan rather
    than an unbounded one.
    """
    from effects.vocabulary import ListDir

    if not path:
        return f"**{label}**\n`(unknown)`\n```\n(unavailable)\n```"

    result = yield ListDir(root=path, recursive=True)
    if not result.ok:
        return f"**{label}**\n`{path}`\n```\n({result.error})\n```"

    value = result.value or {}
    names = set()
    for entry in value.get("entries", []):
        rel = (entry.get("path") or "").strip()
        if not rel:
            continue
        head, _, tail = rel.partition("/")
        names.add(head + "/" if tail else head)
    listing = "\n".join(sorted(names, key=lambda n: (not n.endswith("/"), n.lower())))
    if value.get("truncated"):
        listing += "\n… (listing truncated)"
    return f"**{label}**\n`{path}`\n```\n{listing or '(empty)'}\n```"
