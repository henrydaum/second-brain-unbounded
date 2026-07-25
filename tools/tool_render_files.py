"""render_files — show local files to the user in chat.

A ``Stat`` per path checks existence (root-confined, kernel-side); the terminal
``Respond`` carries the valid paths as attachments, which the frontend renders.
"""

from plugins.BaseTool import BaseTool
from effects.vocabulary import Stat, Respond

MAX_FILES = 10


class RenderFilesTool(BaseTool):
    contract = "effects"
    name = "render_files"
    description = (
        "Display one or more local files to the user in chat with an optional caption. Always "
        "use this for images, audio, and video — a description is not a substitute. Use it "
        "for documents the user asked to find or open. Skip it when your text reply already "
        "covers the content. Max 10 per call. List the file `paths` to show (max 10). Add a "
        "`caption` when the message is about the files — it replaces a separate text reply."
    )
    parameters = {
        "type": "object",
        "properties": {
            "paths": {"type": "array", "items": {"type": "string"}, "description": "File paths to display. Maximum 10 per call."},
            "caption": {"type": "string", "description": "Optional short text shown alongside the files in the same chat turn."},
        },
        "required": ["paths"],
    }
    declared_requests = ["stat"]
    view = "params_only"
    max_calls = 5

    def run(self, params):
        paths = params.get("paths") or []
        caption = (params.get("caption") or "").strip()
        if not paths:
            return Respond(summary="render_files failed: no file paths provided.", success=False, error="no paths")

        valid, missing = [], []
        for p in paths:
            info = yield Stat(path=p)
            if info.ok and info.value.get("exists"):
                valid.append(p)
            else:
                missing.append(p)

        if not valid:
            msg = f"None of the provided paths exist: {missing}. If you guessed them, try hybrid_search first."
            return Respond(summary="render_files failed: " + msg, success=False, error=msg)

        skipped = max(0, len(valid) - MAX_FILES)
        valid = valid[:MAX_FILES]
        notes = []
        if skipped:
            notes.append(f"Skipped {skipped} extra path(s) — {MAX_FILES}-file limit per call.")
        if missing:
            notes.append(f"Missing: {missing}")

        if caption:
            summary = caption + ("\n\n(" + " ".join(notes) + ")" if notes else "")
        else:
            names = ", ".join(p.replace("\\", "/").split("/")[-1] for p in valid)
            summary = f"Rendered {len(valid)} file(s) to the user: {names}." + (" " + " ".join(notes) if notes else "")

        return Respond(summary=summary, data={"caption": caption} if caption else None, attachment_paths=valid)
