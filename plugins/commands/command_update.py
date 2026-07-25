"""Slash command plugin for `/update`."""

from plugins.BaseCommand import BaseCommand


class UpdateCommand(BaseCommand):
    """Slash-command handler for `/update`.

    The simplest proof that a real kernel command runs on the effects contract:
    the body is a generator, its only capability is ``RunProcess``, and git is
    reached through the kernel rather than through ``subprocess`` in the plugin's
    own address space. What used to be an unmediated shell call is now four
    declared, root-confined, ledger-recorded requests.
    """
    name = "update"
    description = "Pull latest changes from the Second Brain repo"
    category = "Config & System"
    require_approval = True
    approval_actor_id = "user"

    contract = "effects"
    declared_requests = ["run_process", "read_context"]

    def run(self, _params):
        """Execute `/update` for the active session."""
        from effects.vocabulary import ReadContext, Respond

        paths = yield ReadContext(view="paths")
        root = (paths.value or {}).get("root") or ""

        before = yield from _git(root, "rev-parse", "HEAD")
        if not before.ok:
            return Respond(data=f"Update failed: {before.error}")

        pull = yield from _git(root, "pull")
        if not pull.ok:
            return Respond(data=f"Update failed: {pull.error}")
        if pull.code:
            return Respond(data=f"git pull failed (exit {pull.code}):\n{pull.err or pull.out}")
        if not pull.out or pull.out.lower().startswith("already up to date"):
            return Respond(data=pull.out or "Already up to date.")

        after = yield from _git(root, "rev-parse", "HEAD")
        if not after.ok or before.out == after.out:
            return Respond(data=pull.out)

        log = yield from _git(root, "log", "--pretty=format:- %s", f"{before.out}..{after.out}")
        summary = (log.out if log.ok else "") or pull.out
        return Respond(data=(f"Updated {before.out[:7]}..{after.out[:7]}:\n\n"
                             f"{summary}\n\n/restart to take effect"))


class _Run:
    """One git invocation's outcome, flattened so the body above reads like the
    imperative version it replaces."""

    def __init__(self, result):
        """Unpack a RunProcess EffectResult."""
        value = result.value or {}
        self.ok = bool(result.ok)
        self.error = result.error or ""
        self.code = value.get("exit_code", 0)
        self.out = (value.get("stdout") or "").strip()
        self.err = (value.get("stderr") or "").strip()


def _git(root: str, *args):
    """Yield one git call and return its flattened outcome."""
    from effects.vocabulary import RunProcess

    result = yield RunProcess(argv=["git", *args], cwd=root, timeout=60.0)
    return _Run(result)
