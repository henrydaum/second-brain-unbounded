"""use_skill — load one installed skill's full SKILL.md into context.

Counterpart to the skills service's prompt index: the system prompt carries
only each skill's name + description; this tool returns the whole SKILL.md
when the agent decides a skill applies. Sandboxed, so it does not call the
skills service — it discovers skills by scanning the ``skills_roots`` exposed
via ``ReadContext("paths")`` (one ``skills/`` folder per plugin root) with
ListDir + ReadFile, mirroring ``service_skills.scan``/``read`` purely.
"""

import sandbox_kit as kit
from plugins.BaseTool import BaseTool
from effects.vocabulary import ReadContext, ListDir, ReadFile, Respond

SKILL_FILENAME = "SKILL.md"
MAX_SUPPORT_FILES = 50


class UseSkillTool(BaseTool):
    contract = "effects"
    name = "use_skill"
    description = (
        "Load the full instructions of an installed skill by name. Call this as soon as a "
        "request matches a skill in the Skills index, before attempting the task. The index "
        "holds only summaries — this returns the actual playbook. Give the `name` of the "
        "skill exactly as it appears in the Skills index."
    )
    parameters = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Skill name exactly as listed in the Skills index."},
        },
        "required": ["name"],
    }
    declared_requests = ["read_file", "list_dir"]
    view = "params_only"
    max_calls = 5
    background_safe = True

    def run(self, params):
        want = (params.get("name") or "").strip().lower()
        if not want:
            return Respond(summary="use_skill failed: no skill name given.", success=False, error="no name")

        paths = yield ReadContext(view="paths")
        roots = (paths.value or {}).get("skills_roots") or []
        if not roots:
            return Respond(summary="use_skill: no skills are installed.", success=False, error="no skills")

        # Discover every skill across all roots; later roots win on name collision
        # (matches plugin-discovery precedence). skills[name] = (root, folder, text).
        skills = {}
        for root in roots:
            listing = yield ListDir(root=root, recursive=True)
            for entry in (listing.value or {}).get("entries", []):
                rel = entry["path"]
                if not (rel == SKILL_FILENAME or rel.endswith("/" + SKILL_FILENAME)):
                    continue
                res = yield ReadFile(path=kit.join_root(root, rel))
                if not res.ok:
                    continue
                folder = rel[: -(len(SKILL_FILENAME) + 1)] if "/" in rel else ""
                name = _skill_name(res.value, folder)
                if name:
                    skills[name] = (root, folder, res.value)

        hit = skills.get(want)
        if hit is None:
            known = ", ".join(sorted(skills)) or "(none installed)"
            return Respond(summary=f"use_skill: no skill named '{want}'. Installed skills: {known}",
                           success=False, error="no such skill")

        root, folder, text = hit
        # Re-list the winning root once to enumerate this skill's support files.
        listing = yield ListDir(root=root, recursive=True)
        prefix = (folder + "/") if folder else ""
        support = sorted(
            e["path"][len(prefix):]
            for e in (listing.value or {}).get("entries", [])
            if e["path"].startswith(prefix) and not e["path"].endswith("/" + SKILL_FILENAME)
            and e["path"] != SKILL_FILENAME
        )[:MAX_SUPPORT_FILES]
        if support:
            text = text.rstrip() + (
                "\n\n---\nSupport files in this skill's folder: "
                + ", ".join(support)
                + ". Read them with read_file if the instructions reference them."
            )
        return Respond(summary=text, data={"skill": want})


def _skill_name(text: str, folder: str) -> str:
    """Skill name from ``--- name: ... ---`` frontmatter, folder name as fallback.
    Mirrors service_skills._parse_skill: names are lowercased."""
    meta = _frontmatter(text)
    name = (meta.get("name") or (folder.rsplit("/", 1)[-1] if folder else "")).strip().lower()
    return name


def _frontmatter(text: str) -> dict:
    """Minimal ``--- key: value ---`` header parser (no YAML dependency).
    Enough to recover a skill's ``name`` scalar; block scalars are ignored."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    out = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        key, sep, value = line.partition(":")
        if sep and key.strip() and not key.startswith(" "):
            out[key.strip().lower()] = value.strip().strip('"').strip("'")
    return out
