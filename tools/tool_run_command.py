"""run_command — run a subprocess: the shell as one mediated, gated verb.

Yields a single ``RunProcess`` request. RunProcess is egress-tier, so every
command is routed through the approval surface before it runs — the kernel owns
the handle, confines the working directory to the allowed roots, and caps the
output. ``command`` is an argv **list**, never a shell string (no shell parsing,
no injection surface). Pure read commands (ls, cat, grep, find) belong in the
dedicated read tools — read_file, glob, grep — not here.
"""

import sandbox_kit as kit
from plugins.BaseTool import BaseTool
from effects.vocabulary import RunProcess, Respond

MAX_STREAM = 20_000


class RunCommandTool(BaseTool):
    contract = "effects"
    name = "run_command"
    description = (
        "Run a subprocess and return its output. Give the command as an argv list (e.g. "
        "[\"git\", \"status\"]) — it is executed directly, without a shell, so no "
        "pipes/globs/redirection. Every command pauses for your approval before it runs; the "
        "working directory is confined to the project and data roots. For reading files or "
        "searching, use read_file / glob / grep instead. Give `command` as an argv list, e.g. "
        "[\"npm\", \"test\"]. No shell syntax (pipes/globs won't work). Add a `justification`; "
        "set `cwd`/`timeout` if needed."
    )
    parameters = {
        "type": "object",
        "properties": {
            "command": {"type": "array", "items": {"type": "string"}, "description": "Argv list, e.g. [\"git\", \"log\", \"-n\", \"5\"]. First element is the program."},
            "cwd": {"type": "string", "description": "Working directory (absolute or relative to the project root). Defaults to the project root."},
            "timeout": {"type": "integer", "description": "Seconds before the process is killed. Default 60, max 600."},
            "justification": {"type": "string", "description": "Short reason for the command, shown in the approval dialog."},
        },
        "required": ["command"],
    }
    declared_requests = ["run_process"]
    view = "params_only"
    max_calls = 20
    background_safe = False

    def run(self, params):
        argv = params.get("command") or []
        if isinstance(argv, str):
            argv = argv.split()  # tolerate a bare string, but an array is preferred
        argv = [str(a) for a in argv if str(a).strip()]
        if not argv:
            return Respond(summary="run_command failed: no command given.", success=False, error="no command")
        timeout = kit.clamp(params.get("timeout"), 1, 600, 60)

        res = yield RunProcess(argv=argv, cwd=(params.get("cwd") or ""), timeout=float(timeout))
        if not res.ok:
            if res.denied:
                return Respond(
                    summary="run_command: denied by user. STOP — do not retry; ask what to do instead.",
                    success=False, error=res.error or "denied")
            return Respond(summary="run_command failed: " + res.error, success=False, error=res.error)

        v = res.value
        return Respond(summary=_format(argv, v), data=v, success=(v.get("exit_code") == 0))


def _format(argv, v) -> str:
    """Render the process result as compact markdown for the model."""
    parts = ["$ " + " ".join(argv), f"(exit {v.get('exit_code')}, {v.get('duration')}s)"]
    out, _ = kit.truncate_chars(v.get("stdout") or "", MAX_STREAM)
    err, _ = kit.truncate_chars(v.get("stderr") or "", MAX_STREAM)
    if out.strip():
        parts.append("stdout:\n" + out)
    if err.strip():
        parts.append("stderr:\n" + err)
    if v.get("truncated"):
        parts.append("(output truncated)")
    return "\n\n".join(parts)
