"""Slash command plugin for `/tasks`."""

from plugins.BaseCommand import BaseCommand

PATH_ACTIONS = ["pause", "unpause", "reset", "retry"]
EVENT_ACTIONS = ["pause", "unpause", "trigger"]
PIPELINE = "Show pipeline"


class TasksCommand(BaseCommand):
    """Slash-command handler for `/tasks`.

    ``TaskControl`` covers all five actions in one verb rather than splitting
    further, because they share a grade for two overlapping reasons: ``reset``
    and ``retry`` discard processing state no journal captured, and ``trigger``
    *runs* a task. Splitting them would buy nothing — the principal policy
    already makes the human's own ``/tasks`` friction-free, and every action here
    is one an agent should be gated on.

    The pipeline graph crosses as pre-rendered text. The orchestrator knows how
    to draw it, and laying out a dependency graph was never this command's job.
    """
    name = "tasks"
    description = "Pick a task — pause, unpause, reset, retry, or trigger"
    category = "System"

    contract = "effects"
    declared_requests = ["read_context", "task_control"]

    def form(self, params):
        """Offer the task list, then the actions valid for its trigger shape."""
        tasks = yield from _tasks()
        steps = [{"name": "task_name", "required": True, "columns": 2,
                  "prompt": "Select a task to manage, or view the pipeline.",
                  "enum": [*sorted(t["name"] for t in tasks), PIPELINE]}]

        name = params.get("task_name")
        if name == PIPELINE:
            return steps

        task = _find(tasks, name)
        if task:
            actions = EVENT_ACTIONS if task["trigger"] == "event" else PATH_ACTIONS
            steps.append({"name": "action", "required": True, "enum": actions,
                          "prompt": ("What do you want to do with this task?\n\n"
                                     f"{_card(task)}")})
        if task and params.get("action") == "trigger":
            steps += _payload_steps(task)
        return steps

    def run(self, params):
        """Execute `/tasks` for the active session."""
        from effects.vocabulary import ReadContext, Respond, TaskControl

        name = params.get("task_name")
        if name == PIPELINE:
            graph = yield ReadContext(view="pipeline")
            return Respond(data=graph.value or "Pipeline unavailable.")

        tasks = yield from _tasks()
        if not name:
            return Respond(data=_listing(tasks))

        task = _find(tasks, name)
        if task is None:
            return Respond(data="Unknown task.")

        action = params.get("action")
        if not action:
            return Respond(data=_card(task))
        if action not in (*PATH_ACTIONS, "trigger"):
            return Respond(data=f"Unknown action: {action}")

        payload = None
        if action == "trigger":
            keys = (task.get("event_payload_schema") or {}).get("properties", {}).keys()
            payload = {key: params[key] for key in keys if key in params}

        result = yield TaskControl(name=name, action=action, payload=payload)
        if not result.ok:
            return Respond(data=f"Could not {action} {name}: {result.error}")

        if action == "trigger":
            return Respond(data=f"Triggered task: {name} ({(result.value or {}).get('run_id')})")
        past = {"pause": "Paused", "unpause": "Unpaused",
                "reset": "Reset", "retry": "Retried failed entries for"}[action]
        return Respond(data=f"{past} task: {name}")


def _tasks():
    """Yield the tasks inventory."""
    from effects.vocabulary import ReadContext

    result = yield ReadContext(view="tasks")
    return result.value or []


def _find(tasks, name):
    """One task's inventory entry, or None."""
    return next((t for t in tasks if t["name"] == name), None) if name else None


def _payload_steps(task) -> list[dict]:
    """Form steps for an event task's payload, from its declared schema."""
    schema = task.get("event_payload_schema") or {}
    required = set(schema.get("required") or [])
    steps = []
    for name, spec in (schema.get("properties") or {}).items():
        step = {"name": name, "required": name in required,
                "prompt": spec.get("description") or name,
                "prompt_when_missing": True}
        if spec.get("type") in ("array", "boolean", "integer", "number"):
            step["type"] = spec["type"]
        if spec.get("enum"):
            step["enum"] = list(spec["enum"])
        steps.append(step)
    return steps


def _listing(tasks) -> str:
    """The task table, grouped by trigger shape."""
    import sandbox_kit as kit

    if not tasks:
        return "No tasks are registered."
    rows = []
    for task in tasks:
        counts = {"PENDING": 0, "PROCESSING": 0, "DONE": 0, "FAILED": 0} | (task["counts"] or {})
        rows.append((task["name"] + (" (paused)" if task["paused"] else ""),
                     task["trigger"], counts["PENDING"], counts["PROCESSING"],
                     counts["DONE"], counts["FAILED"]))
    return "Tasks:\n\n" + kit.md_table(
        ["Task", "Trigger", "Pending", "Running", "Done", "Failed"], rows)


def _card(task) -> str:
    """A describe card for one task."""
    import sandbox_kit as kit

    counts = {"PENDING": 0, "PROCESSING": 0, "DONE": 0, "FAILED": 0} | (task["counts"] or {})
    pairs = [("Trigger", task["trigger"]),
             ("Paused", "yes" if task["paused"] else "no"),
             ("Pending", counts["PENDING"]), ("Running", counts["PROCESSING"]),
             ("Done", counts["DONE"]), ("Failed", counts["FAILED"])]
    if task.get("requires_services"):
        pairs.append(("Requires", ", ".join(task["requires_services"])))

    card = kit.detail_card(task["name"], pairs)
    scheduled = task.get("scheduled_jobs") or 0
    if scheduled:
        card += f"\n\nScheduled jobs: {scheduled}. Use /schedule to manage them."
    return card
