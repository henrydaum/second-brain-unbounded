"""In-memory broker for deterministic plugin unit tests."""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Mapping


class FakeBroker:
    def __init__(self):
        self.handlers: dict[
            str, Callable[[Mapping[str, Any]], Any | Awaitable[Any]]] = {}
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def handle(self, right: str,
               fn: Callable[[Mapping[str, Any]], Any | Awaitable[Any]]) -> None:
        self.handlers[right] = fn

    async def request(self, right: str, payload: Mapping[str, Any]) -> Any:
        copied = dict(payload)
        self.requests.append((right, copied))
        handler = self.handlers.get(right)
        if handler is None:
            return {"denied": True, "error": f"no fake handler for {right}"}
        value = handler(copied)
        return await value if inspect.isawaitable(value) else value

