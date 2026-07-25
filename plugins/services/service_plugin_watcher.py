"""Plugin hot-reload — on the effects contract.

This service cited two capabilities: #2 (a watchdog ``Observer`` thread) and #3
(it called ``load_single_plugin``/``unload_plugin`` directly, mutating every
kernel registry). Both exits existed and neither had been used:
``runtime/service_ticker.py`` was never started by bootstrap, and ``ReloadPlugin``
had a vocabulary entry, a docstring, and a test but no provider on any context.

So this file is now what a hot-reloader looks like when it may not touch
anything: **a diff.** It lists the plugin directories, compares mtimes against
what it saw last tick, and names the paths that changed. Loading them —
inferring the family, clearing strike counts, rewiring peer services, refreshing
command specs and the LLM router, announcing the result — is kernel work behind
``ReloadPlugin`` (``plugins/helpers/plugin_reload.py``).

Two deliberate behaviour notes:

- **Polling replaces inotify.** A change is noticed within a tick or two rather
  than instantly. That is the acceptable cost: a hot-reload path is not latency
  critical, and the ``Observer`` was the entire reason for capability #2.
- **A change must be stable for one tick before it is loaded.** The old code
  debounced filesystem events by a second for the same reason — an editor's save
  is not atomic, and importing a half-written file registers a plugin that never
  existed. Requiring the mtime to repeat is the polling spelling of that
  debounce, and it is why ``_pending`` exists.

Quarantine is no longer handled here. The supervisor's circuit breaker condemns
a plugin by emitting on the bus, and unloading it is registry mutation — so the
kernel subscribes and does it (``runtime/bootstrap.py``), rather than this
service holding a subscription and a set of live registries.
"""

from plugins.BaseService import BaseService, EXTENSION

# Load order within one batch: services must register before the tasks that
# require them, so a batch install (many files landing at once) doesn't leave
# tasks warning about missing services. Lower loads first; unknown types last.
_LOAD_PRIORITY = {"service_": 0, "task_": 1, "tool_": 2, "command_": 3, "frontend_": 4}


class PluginWatcherService(BaseService):
    """Notices changed plugin files and asks the kernel to (re)load them."""

    model_name = "Plugin Watcher"
    shared = True
    lifecycle = EXTENSION

    contract = "effects"
    declared_requests = ["read_context", "list_dir", "reload_plugin"]
    tick_interval_s = 1.0

    def __init__(self, config: dict = None):
        """Initialize the plugin watcher service.

        State lives on the instance and survives between ticks: a service's
        sandbox is persistent, so the child process that ran the last tick runs
        the next one. ``_seen`` is the mtime baseline, ``_pending`` the
        one-tick debounce."""
        super().__init__()
        self._seen: dict[str, float] = {}
        self._pending: dict[str, float] = {}
        self._quarantined: set[str] = set()
        self._primed = False

    def tick(self, params):
        """Reload whatever changed since the last tick.

        The first tick only takes a baseline — every plugin on disk is already
        loaded by discovery at boot, so treating them all as new would reload
        the entire tree one second after startup."""
        from effects.vocabulary import ListDir, ReadContext, ReloadPlugin, Respond

        paths = yield ReadContext(view="paths")
        directories = list((paths.value or {}).get("plugin_dirs") or [])

        current: dict[str, float] = {}
        for directory in directories:
            listing = yield ListDir(root=directory, recursive=False)
            for entry in ((listing.value or {}).get("entries") or []):
                name = entry.get("path") or ""
                if not name.endswith(".py") or name.startswith("_"):
                    continue
                current[f"{directory}/{name}"] = float(entry.get("mtime") or 0.0)

        condemned = yield ReadContext(view="quarantined_plugins")
        condemned = {str(p) for p in (condemned.value or [])}

        if not self._primed:
            self._seen, self._primed = current, True
            return Respond(data=[])

        changed = self._settled(current)
        removed = [path for path in self._seen if path not in current]

        results = []
        for path in sorted(changed, key=_priority):
            outcome = yield ReloadPlugin(path=path, action="reload")
            # The baseline advances only once the load has been attempted. If it
            # advanced with the scan instead, a file noticed on one tick would
            # look unchanged on the next and never be loaded at all.
            self._seen[path] = current[path]
            results.append({"path": path, "action": "reload",
                            "ok": bool(outcome.ok), "result": outcome.value})
        for path in removed:
            self._seen.pop(path, None)
            self._pending.pop(path, None)
            outcome = yield ReloadPlugin(path=path, action="unload")
            results.append({"path": path, "action": "unload",
                            "ok": bool(outcome.ok), "result": outcome.value})

        # Plugins the supervisor's circuit breaker condemned. The file stays on
        # disk, so this is the one unload not driven by a filesystem change --
        # and it is why the watcher reads condemned state rather than
        # subscribing to the quarantine channel: a bus subscription plus the
        # registries to act on it was two of the three capabilities that kept
        # this service permanently trusted.
        for path in sorted(condemned - self._quarantined):
            self._quarantined.add(path)
            outcome = yield ReloadPlugin(path=path, action="unload")
            results.append({"path": path, "action": "quarantine",
                            "ok": bool(outcome.ok), "result": outcome.value})
        # A reload clears the condemnation, so forgetting it here is what lets a
        # fixed-and-resaved plugin be quarantined again if it misbehaves again.
        self._quarantined &= condemned
        return Respond(data=results)

    def _settled(self, current: dict) -> list[str]:
        """Paths whose mtime changed and has since held still for one tick.

        A file is only offered for loading on the tick *after* the one that
        noticed it, and only if its mtime did not move in between — so a save
        still being flushed is seen twice with different mtimes and waits."""
        settled = []
        for path, mtime in current.items():
            baseline = self._seen.get(path)
            if baseline is not None and abs(mtime - baseline) < 0.001:
                self._pending.pop(path, None)
                continue
            if self._pending.get(path) == mtime:
                self._pending.pop(path, None)
                settled.append(path)
            else:
                self._pending[path] = mtime
        return settled


def _priority(path: str) -> int:
    """Load order for one path, by its filename prefix."""
    name = path.rsplit("/", 1)[-1]
    for prefix, rank in _LOAD_PRIORITY.items():
        if name.startswith(prefix):
            return rank
    return len(_LOAD_PRIORITY)


def build_services(config: dict) -> dict:
    """Build services."""
    return {"plugin_watcher": PluginWatcherService(config)}
