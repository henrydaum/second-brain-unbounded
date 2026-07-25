"""Slash command plugin for `/services`."""

from plugins.BaseCommand import BaseCommand


class ServicesCommand(BaseCommand):
    """Slash-command handler for `/services`.

    Three capabilities, each now a request instead of a live reach:
    ``ReadContext("services")`` for the listing, ``ServiceControl`` for
    load/unload (was calling ``svc.load()`` on the object), and ``WriteConfig``
    for the autoload list (was ``config_manager.save`` plus a write-through into
    ``runtime.config``, which the plugin had to remember to do).

    The setting *quicklinks* the imperative version offered are deliberately not
    carried over yet — they reached into ``command_config``'s internals for the
    current value of each setting, which is a ``ReadConfig`` and belongs with the
    /config conversion.
    """
    name = "services"
    description = "Inspect services and load or unload managed ones"
    category = "System"

    contract = "effects"
    declared_requests = ["read_context", "service_control", "write_config",
                         "read_config"]

    def form(self, params):
        """Offer the service list, then the actions valid for the chosen one."""
        services = (yield from _services())
        steps = [{"name": "service_name", "prompt": "Select a service.",
                  "required": True, "enum": sorted(s["name"] for s in services),
                  "columns": 2}]

        chosen = _find(services, params.get("service_name"))
        if chosen and chosen["user_managed"]:
            steps.append({
                "name": "action", "required": True,
                "prompt": f"What do you want to do with this service?\n\n{_card(chosen)}",
                "enum": ["toggle_loaded", "toggle_autoload"],
                "enum_labels": ["Unload it" if chosen["loaded"] else "Load it",
                                "Don't autoload on startup" if chosen["autoload"]
                                else "Autoload on startup"]})
        return steps

    def run(self, params):
        """Execute `/services` for the active session."""
        from effects.vocabulary import (
            ReadConfig, Respond, ServiceControl, WriteConfig)

        services = yield from _services()
        name = params.get("service_name")
        if not name:
            return Respond(data=_listing(services))

        service = _find(services, name)
        if service is None:
            return Respond(data="Unknown service.")

        action = params.get("action")
        if not action:
            return Respond(data=_card(service))
        if not service["user_managed"]:
            return Respond(data=f"{name} is an installed extension and is loaded automatically.")

        if action == "toggle_loaded":
            want = "stop" if service["loaded"] else "start"
            result = yield ServiceControl(name=name, action=want)
            if not result.ok:
                return Respond(data=f"Could not {want} {name}: {result.error}")
            return Respond(data=f"{'Unloaded' if want == 'stop' else 'Loaded'} service: {name}")

        if action == "toggle_autoload":
            # Read the stored list rather than rebuilding it from the inventory:
            # autoload_services can name services that are not registered right
            # now (an extension that failed to load, one whose package is
            # mid-install), and reconstructing from what happens to be loaded
            # would silently drop them.
            current = yield ReadConfig(key="autoload_services")
            names = {str(n) for n in (current.value or []) if str(n)}
            turning_on = name not in names
            names.add(name) if turning_on else names.discard(name)

            result = yield WriteConfig(key="autoload_services", value=sorted(names))
            if not result.ok:
                return Respond(data=f"Could not update autoload: {result.error}")
            return Respond(data=(f"{name} will {'now' if turning_on else 'no longer'} "
                                 "load automatically on startup."))

        return Respond(data=f"Unknown action: {action}")


def _services():
    """Yield the services inventory."""
    from effects.vocabulary import ReadContext

    result = yield ReadContext(view="services")
    return result.value or []


def _find(services, name):
    """The named service's inventory entry, or None."""
    return next((s for s in services if s["name"] == name), None) if name else None


def _listing(services) -> str:
    """The full service table."""
    import sandbox_kit as kit

    if not services:
        return "No services are registered."
    rows = [(s["name"],
             "Extension" if s["extension"] else ("Loaded" if s["loaded"] else "Unloaded"),
             s.get("model_name") or "-",
             kit.badge(s["autoload"]))
            for s in services]
    return "Services:\n\n" + kit.md_table(["Service", "Status", "Model", "Autoload"], rows)


def _card(service) -> str:
    """A describe card for one service."""
    import sandbox_kit as kit

    status = ("Extension" if service["extension"]
              else ("Loaded" if service["loaded"] else "Unloaded"))
    pairs = [("Status", status),
             ("Model", service.get("model_name") or "-"),
             ("Autoload", "yes" if service["autoload"] else "no"),
             ("Contract", service.get("contract") or "legacy")]
    settings = [(s["title"], s["key"]) for s in service.get("settings") or []]
    if settings:
        pairs.append(("Settings", ", ".join(title for title, _ in settings)))
    return kit.detail_card(service["name"], pairs)
