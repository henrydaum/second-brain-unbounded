"""Clean-break async tool template."""


async def run(ctx, params):
    """Handlers receive only an InvocationContext and JSON parameters."""
    notes = ctx.resources["notes"]
    text = await ctx.files.read_text(notes, params["input"])
    return {
        "summary": f"Read {params['input']}",
        "text": text,
    }
