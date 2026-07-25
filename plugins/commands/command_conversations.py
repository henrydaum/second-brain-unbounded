"""/conversations — picker for loading and managing existing chats.

Walks a multi-step form:

    1. Pick a category.
    2. Pick one of the 15 most-recent conversations under the category.
    3. Pick "Load conversation", "Delete conversation", "Change category",
       or "Change notification mode".
        The step prompt previews the chosen conversation's agent and
        most recent messages.
"""

from __future__ import annotations

from plugins.BaseCommand import BaseCommand

_LIMIT = 15
_MAIN = "Main"
_NEW_CAT = "Add New category"
_LOAD = "Load conversation"
_DELETE = "Delete conversation"
_CHANGE_CATEGORY = "Change category"
_CHANGE_NOTIF = "Change notification mode"
_ACTIONS = [_LOAD, _DELETE, _CHANGE_CATEGORY, _CHANGE_NOTIF]


class ConversationsCommand(BaseCommand):
    """Slash-command handler for `/conversations`.

    Uses **two** verbs over one resource, which is the point of splitting them:
    ``ReadConversations`` is read-tier and ownership-scoped, so browsing your own
    history costs nothing; ``ConversationOp`` is egress, so deleting one is
    graded like the irreversible act it is. A single verb would have forced the
    browse to carry the delete's tier, or the delete to carry the browse's.
    """
    name = "conversations"
    description = "Browse, switch, or manage conversations"
    category = "Conversation"

    contract = "effects"
    declared_requests = ["read_conversations", "conversation_op"]

    def form(self, params):
        """Walk category → conversation → action → action-specific value."""
        from effects.vocabulary import ReadConversations

        categories = yield ReadConversations(mode="categories")
        steps = [{"name": "category", "required": True, "columns": 1,
                  "prompt": "Choose a conversation category.",
                  "enum": categories.value or [_MAIN]}]

        picked = params.get("category")
        if not picked:
            return steps

        listing = yield ReadConversations(mode="list", category=picked, limit=_LIMIT)
        rows = listing.value or []
        if not rows:
            steps.append({"name": "conversation_id", "required": True, "columns": 1,
                          "prompt": f"No conversations found under '{picked}'.",
                          "enum": ["(none)"], "enum_labels": ["(none)"]})
            return steps

        steps.append({"name": "conversation_id", "required": True, "columns": 1,
                      "prompt": f"Choose a recent conversation under '{picked}'.",
                      "enum": [str(row["id"]) for row in rows],
                      "enum_labels": [_row_label(row) for row in rows]})

        cid = _decode_id(params.get("conversation_id"))
        if cid is None:
            return steps

        preview = yield ReadConversations(mode="preview", conversation_id=cid)
        steps.append({"name": "action", "required": True, "columns": 1,
                      "enum": _ACTIONS,
                      "prompt": ("What do you want to do with this conversation?\n\n"
                                 f"{_preview_card(preview.value or {})}").strip()})

        action = params.get("action")
        if action == _CHANGE_CATEGORY:
            choices = list(categories.value or [])
            if _MAIN not in choices:
                choices.insert(0, _MAIN)
            steps.append({"name": "target_category", "required": True, "columns": 1,
                          "prompt": "Choose the new category.",
                          "enum": choices + [_NEW_CAT]})
            if params.get("target_category") == _NEW_CAT:
                steps.append({"name": "custom_category", "required": True, "columns": 1,
                              "prompt": "Enter a name for the new category."})
        elif action == _CHANGE_NOTIF:
            steps.append({"name": "mode", "required": True, "columns": 1,
                          "enum": _notification_modes(),
                          "prompt": ("Choose how this conversation should notify you "
                                     "while it runs in the background.")})
        return steps

    def run(self, params):
        """Execute `/conversations` for the active session."""
        from effects.vocabulary import ConversationOp, Respond

        cid = _decode_id(params.get("conversation_id"))
        if cid is None:
            return Respond(data="No conversation selected.")

        action = params.get("action") or _LOAD

        if action == _DELETE:
            result = yield ConversationOp(action="delete", conversation_id=cid)
            if not result.ok or not result.value:
                return Respond(data="No such conversation.")
            return Respond(data=f"Deleted conversation #{cid}.")

        if action == _CHANGE_NOTIF:
            result = yield ConversationOp(action="notification_mode", conversation_id=cid,
                                          fields={"mode": params.get("mode")})
            if not result.ok or result.value is None:
                return Respond(data="No such conversation.")
            return Respond(data=f"Notifications for #{cid} → {result.value}.")

        if action == _CHANGE_CATEGORY:
            label = _resolve_category(params)
            result = yield ConversationOp(
                action="categorize", conversation_id=cid,
                fields={"category": None if label == _MAIN else label})
            if not result.ok or not result.value:
                return Respond(data="No such conversation.")
            return Respond(data=f"Conversation #{cid} moved to '{label}'.")

        # Default: load. The kernel reads the conversation's stored state
        # marker, so the agent profile follows the conversation automatically.
        result = yield ConversationOp(action="load", conversation_id=cid)
        if not result.ok or not result.value:
            return Respond(data="No such conversation.")
        messages = (result.value if isinstance(result.value, list) else []) or []
        text = "\n".join(m for m in messages if m).strip()
        return Respond(data=text or f"Loaded conversation #{cid}.")


class NewCommand(BaseCommand):
    """Start a conversation with default settings."""
    name = "new"
    description = "Start a conversation with default settings"
    category = "Conversation"

    contract = "effects"
    declared_requests = ["read_config", "conversation_op"]

    def run(self, _params):
        """Execute `/new` for the active session."""
        from effects.vocabulary import ConversationOp, ReadConfig, Respond

        profiles = yield ReadConfig(key="llm_profiles")
        if not (profiles.value or {}):
            return Respond(data=("No LLM is configured yet. Run /setup to add one "
                                 "before starting a conversation."))

        result = yield ConversationOp(action="create",
                                      fields={"title": f"New conversation ({_MAIN})",
                                              "kind": "user"})
        if not result.ok or not result.value:
            return Respond(data="Failed to create conversation.")
        new_id = result.value

        loaded = yield ConversationOp(action="load", conversation_id=new_id)
        if not loaded.ok:
            return Respond(data=f"Started new conversation #{new_id}.")
        return Respond(data=f"Started new conversation #{new_id} under '{_MAIN}'.")


def _notification_modes() -> list[str]:
    """The available notification modes.

    Duplicated from ``runtime.notifications`` rather than imported: a sandboxed
    body cannot import kernel modules, and this is a short, stable list. If it
    grows a third state it should become an inventory view instead."""
    return ["all", "mentions", "none"]


def _row_label(row: dict) -> str:
    """Menu label for one conversation row."""
    relative = row.get("relative_time") or ""
    return f"{row['title']}  ({relative})" if relative else row["title"]


def _preview_card(preview: dict) -> str:
    """The scannable header shown once a conversation is picked."""
    import sandbox_kit as kit

    if not preview:
        return ""
    card = kit.detail_card(preview.get("title") or "(untitled)", [
        ("Agent", preview.get("agent") or "(unknown)"),
        ("Notifications", preview.get("notification_mode") or "all"),
    ])
    snippets = preview.get("snippets") or []
    return card + (f"\n\n{kit.quote_block(chr(10).join(snippets))}" if snippets else "")


def _resolve_category(params: dict) -> str:
    """The category label the user chose, honouring the custom-name branch."""
    chosen = (params.get("target_category") or "").strip()
    if chosen == _NEW_CAT:
        return (params.get("custom_category") or "").strip() or _MAIN
    return chosen or _MAIN


def _decode_id(value) -> int | None:
    """Parse a conversation id from a form value or a '#123 title' string."""
    if value in (None, "", "(none)"):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lstrip("#")
    head = text.split(" ", 1)[0].strip()
    try:
        return int(head)
    except (TypeError, ValueError):
        return None
