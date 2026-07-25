"""Slash command plugin for `/packages`."""

from plugins.BaseCommand import BaseCommand

ACTIONS = ["available", "installed", "install", "uninstall", "update"]
ACTION_LABELS = ["Browse available", "Browse installed", "Install", "Uninstall",
                 "Update installed"]
CATEGORIES = ["tools", "tasks", "services", "commands", "frontends", "bundles"]
CATEGORY_LABELS = ["Tools", "Tasks", "Services", "Commands", "Frontends", "Bundles"]
_BLURB = {
    "tools": "agent-callable tools",
    "tasks": "pipeline tasks",
    "services": "persistent backends and helpers",
    "commands": "slash commands",
    "frontends": "chat frontends and helpers",
    "bundles": "named groups of store files",
}


class PackagesCommand(BaseCommand):
    """Browse, install, and uninstall tree-store plugins/helpers.

    The sharpest case for the principal policy in the whole kernel: installing a
    package fetches code from the network and lands it where the kernel will
    later execute it. That is the deferred-execution rule's exact shape, so
    ``PackageOp`` is egress and an untrusted plugin issuing one from an agent
    turn is refused outright.

    Progress reporting moved kernel-side with the conversion. pip can run for
    minutes, and the imperative version passed a callback down into the package
    manager — a live callable, which a sandboxed body cannot hold. The kernel
    already knows which session asked, so it pushes the updates itself.
    """
    name = "packages"
    description = "Browse, install, or uninstall store files by category"
    category = "System"
    agent_prompt = (
        "Installing or uninstalling a package changes the live catalogs: new "
        "tools and commands appear on the next turn, not instantly. After an "
        "install, re-check the tool catalog before concluding a capability is "
        "missing or broken."
    )

    contract = "effects"
    declared_requests = ["read_context", "package_op"]

    def form(self, params):
        """Offer the action, then whatever that action needs."""
        steps = [{"name": "action", "prompt": "Choose a package action.",
                  "required": True, "enum": ACTIONS, "enum_labels": ACTION_LABELS}]
        action = params.get("action")

        if action in ("available", "installed"):
            catalog = yield from _catalog()
            steps.append({
                "name": "category", "required": True, "columns": 2,
                "enum": CATEGORIES, "enum_labels": CATEGORY_LABELS,
                "prompt": _overview(catalog, action) + "\n\nChoose a category."})
        elif action == "install":
            steps.append({"name": "package_id", "required": True,
                          "prompt": "Enter the plugin, helper, or bundle stem to install."})
        elif action == "uninstall":
            catalog = yield from _catalog()
            removable = catalog.get("removable", []) + catalog.get("bundles", [])
            steps.append({"name": "package_id", "required": True, "columns": 2,
                          "enum": [item["id"] for item in removable],
                          "prompt": "Choose the plugin, helper, or bundle stem to uninstall."})
        return steps

    def run(self, params):
        """Execute `/packages` for the active session."""
        from effects.vocabulary import PackageOp, Respond

        action = params.get("action") or "installed"

        if action in ("available", "installed"):
            catalog = yield from _catalog()
            return Respond(data=_browse(catalog, action, params.get("category")))

        if action in ("install", "uninstall", "update"):
            target = params.get("package_id", "")
            if action != "update" and not target:
                return Respond(data=f"Which package do you want to {action}?")
            result = yield PackageOp(name=target, action=action)
            if not result.ok:
                return Respond(data=f"Package {action} failed: {result.error}")
            return Respond(data=(result.value or {}).get("text") or f"{action} complete.")

        return Respond(data=f"Unknown action: {action}")


def _catalog():
    """Yield the package catalog — available, installed, removable, bundles."""
    from effects.vocabulary import ReadContext

    result = yield ReadContext(view="packages")
    return result.value or {}


def _browse(catalog: dict, action: str, category: str | None) -> str:
    """The listing for one action, optionally narrowed to a category."""
    if not category:
        return (_overview(catalog, action)
                + f"\n\nChoose a category with /packages {action} <category>.")

    items = [item for item in catalog.get(action, []) if item.get("family") == category]
    label = _label(category).lower()
    if not items:
        return (f"No available {label} files." if action == "available"
                else f"No {label} files installed.")

    verb = "install" if action == "available" else "uninstall"
    return "\n\n".join([_heading(action.capitalize(), category),
                        _items_table(items),
                        f"{verb.capitalize()} with `/packages {verb} <name>`."])


def _overview(catalog: dict, action: str) -> str:
    """Per-category counts for available or installed files."""
    import sandbox_kit as kit

    counts = {}
    for item in catalog.get(action, []):
        family = item.get("family")
        counts[family] = counts.get(family, 0) + 1
    header = ("Installed files by category:" if action == "installed"
              else "Available files by category:")
    rows = [(label, counts.get(cat, 0), _BLURB[cat])
            for cat, label in zip(CATEGORIES, CATEGORY_LABELS)]
    return header + "\n\n" + kit.md_table(["Category", "Count", "What"], rows)


def _items_table(items: list[dict]) -> str:
    """Name/path table for a category's files."""
    import sandbox_kit as kit

    rows = [(item["id"] + (" (helper)" if item.get("helper") else ""), item["path"])
            for item in items]
    return kit.md_table(["Name", "Path"], rows)


def _heading(prefix: str, category: str) -> str:
    """Section heading, singularised for plugin families."""
    if category == "bundles":
        return f"{prefix} bundles:"
    label = _label(category).lower()
    return f"{prefix} {label[:-1] if label.endswith('s') else label} plugins:"


def _label(category: str) -> str:
    """Display label for a category key."""
    return (CATEGORY_LABELS[CATEGORIES.index(category)]
            if category in CATEGORIES else (category or ""))
