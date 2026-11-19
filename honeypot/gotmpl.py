# Go Template Renderer
# the small text/template subset the aish persona files use, so the same JSON works in both
# {{ .Username }} - field lookup
# {{ promptSymbol .Username }} - single-argument function call
# anything else is left as it is, so an unknown directive shows up instead of ending a session

# Imports
from __future__ import annotations

import re
from typing import Any, Callable, Mapping

_FIELD = re.compile(r"\{\{\s*\.(\w+)\s*\}\}")
_CALL = re.compile(r"\{\{\s*(\w+)\s+\.(\w+)\s*\}\}")


# Prompt symbol - # for root and $ for everyone else, like bash's \$ expansion
def prompt_symbol(username: str) -> str:
    return "#" if username == "root" else "$"


FUNCS: dict[str, Callable[[Any], str]] = {
    "promptSymbol": prompt_symbol,
}


# Render text against ctx
# keys are the Go field names, such as Username
def render(text: str, ctx: Mapping[str, Any]) -> str:
    def _call(m: re.Match[str]) -> str:
        fn, field = m.group(1), m.group(2)
        if fn not in FUNCS or field not in ctx:
            return m.group(0)
        return str(FUNCS[fn](ctx[field]))

    def _field(m: re.Match[str]) -> str:
        key = m.group(1)
        return str(ctx[key]) if key in ctx else m.group(0)

    # Calls first - {{ promptSymbol .Username }} matches nothing in _FIELD anyway
    # but the order keeps the intent obvious
    return _FIELD.sub(_field, _CALL.sub(_call, text))
