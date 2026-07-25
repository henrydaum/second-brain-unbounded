"""sql_query — run SQL against the local database.

Read-only statements (SELECT / PRAGMA / EXPLAIN) go through the ungated,
read-only-guarded ``QueryDb``. Any mutating statement goes through ``ExecSql``,
which is egress-tier and gated — the kernel pauses for the user to approve the
exact SQL. On error the tool issues a few more read queries (sqlite_master /
PRAGMA) to build a schema hint. All formatting is pure ``sandbox_kit``.
"""

import re
from difflib import get_close_matches

import sandbox_kit as kit
from plugins.BaseTool import BaseTool
from effects.vocabulary import QueryDb, ExecSql, Respond

_READ_ONLY_PREFIXES = ("select", "pragma", "explain")


def _is_read_only(sql: str) -> bool:
    """True for SELECT / PRAGMA / EXPLAIN. Anything else (incl. WITH…INSERT) is
    conservatively a mutation — worst case an extra approval, never a silent
    unapproved write."""
    return " ".join(sql.strip().split()).lower().startswith(_READ_ONLY_PREFIXES)


class SqlQueryTool(BaseTool):
    contract = "effects"
    name = "sql_query"
    description = (
        "Run one SQL statement against the local file database. SELECT / PRAGMA / EXPLAIN run "
        "immediately (capped rows) — use them to inspect schema, file metadata, pipeline "
        "state, extracted text, and stored conversations. Mutating statements (INSERT / "
        "UPDATE / DELETE / DDL) are allowed but each pauses for explicit user approval of the "
        "exact SQL, so give a clear `justification`. Default to read-only; only write when "
        "the user asked you to. Write one SQL statement in `sql`. Explore with SELECT / "
        "PRAGMA first. Only write (INSERT/UPDATE/DELETE/DDL) if the user asked — and add a "
        "`justification`."
    )
    parameters = {
        "type": "object",
        "properties": {
            "sql": {"type": "string", "description": "A single SQL statement. SELECT/PRAGMA/EXPLAIN run immediately; a mutating statement requires user approval first."},
            "justification": {"type": "string", "description": "Short plain-English reason for a mutating statement, shown in the approval dialog. Ignored for reads."},
        },
        "required": ["sql"],
    }
    declared_requests = ["query_db", "exec_sql"]
    view = "params_only"
    max_calls = 6  # failed queries are common; allow a few retries

    def run(self, params):
        sql = (params.get("sql") or "").strip()
        if not sql:
            return Respond(summary="sql_query failed: no SQL provided.", success=False, error="no SQL provided")

        if _is_read_only(sql):
            res = yield QueryDb(sql=sql)
            if not res.ok:
                hint = yield from self._schema_hint(res.error)
                return Respond(summary="sql_query failed: " + res.error + hint, success=False, error=res.error)
            v = res.value
            cols, rows, trunc = v["columns"], v["rows"], v.get("truncated", False)
            return Respond(summary=_read_summary(sql, cols, rows, trunc), data={
                "columns": cols, "rows": rows, "row_count": len(rows), "truncated": trunc, "wrote": False})

        res = yield ExecSql(sql=sql)
        if not res.ok:
            if res.denied:
                return Respond(
                    summary="sql_query: write denied by user. STOP — do not retry; ask what to do instead.",
                    success=False, error=res.error or "denied")
            hint = yield from self._schema_hint(res.error)
            return Respond(summary="sql_query failed: " + res.error + hint, success=False, error=res.error)
        rowcount = (res.value or {}).get("rowcount")
        return Respond(summary=_write_summary(sql, rowcount), data={"rowcount": rowcount, "wrote": True})

    def _schema_hint(self, error_msg):
        """Yield read queries to build a table/column hint for a failed statement."""
        res = yield QueryDb(sql="SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        if not res.ok or not res.value["rows"]:
            return ""
        tables = [r[0] for r in res.value["rows"]]
        lines = ["\n\nAvailable tables: " + ", ".join(tables)]

        m = re.search(r"no such table:\s*(\S+)", error_msg or "")
        if m:
            guesses = get_close_matches(m.group(1), tables, n=2, cutoff=0.5)
            if guesses:
                lines.append("Did you mean: " + ", ".join(guesses) + "?")
            return "\n".join(lines)

        m = re.search(r"no such column:\s*(\S+)", error_msg or "")
        if m:
            bad_col = m.group(1).split(".")[-1]
            suggestions = []
            for t in tables:
                cols_res = yield QueryDb(sql=f"PRAGMA table_info({t})")
                if not cols_res.ok:
                    continue
                cols = [r[1] for r in cols_res.value["rows"]]
                if bad_col in cols:
                    suggestions.append(f"{t}: {', '.join(cols)}")
                else:
                    close = get_close_matches(bad_col, cols, n=1, cutoff=0.6)
                    if close:
                        suggestions.append(f"{t} has '{close[0]}' (cols: {', '.join(cols)})")
            if suggestions:
                lines.append("Column hints:")
                lines.extend("  " + s for s in suggestions[:5])
        return "\n".join(lines)


def _cap(value, limit: int = 500) -> str:
    """Stringify a cell, truncating very long values."""
    s = str(value)
    return s if len(s) <= limit else s[:limit] + f"...[+{len(s) - limit} chars]"


def _read_summary(sql, columns, rows, truncated) -> str:
    note = " (truncated)" if truncated else ""
    header = f"SQL: {sql}\n\nReturned {len(rows)} row(s){note}."
    if not rows:
        return header
    return header + "\n\n" + kit.md_table(columns, [[_cap(v) for v in row] for row in rows])


def _write_summary(sql, rowcount) -> str:
    affected = "an unknown number of" if rowcount is None or (isinstance(rowcount, int) and rowcount < 0) else str(rowcount)
    return f"SQL: {sql}\n\nStatement executed. Rows affected: {affected}."
