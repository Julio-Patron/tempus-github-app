"""Reject repeated JSON object keys.

``tempus-ddb`` 0.5.3 does not export a strict parser. On the ``desarrollo`` branch the
Rust helper ``strict_json::parse`` rejects repeated keys, but it is ``pub(crate)`` and
``verify_and_consume_permit`` still parses with ``serde_json::from_str`` (last key wins).
Until the core exposes ``tempus_ddb.strict_loads``, this module is the local equivalent.

TODO: drop the ``object_pairs_hook`` when that symbol exists.
https://github.com/Julio-Patron/tempus-ddb/issues/86
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

DUPLICATE_JSON_KEY = "DUPLICATE_JSON_KEY"

# Public name proposed for the core. Checked first so a future export replaces this hook.
_CORE_PARSER_NAMES = ("strict_loads", "parse_strict_json")


def _core_parser() -> Callable[[str], Any] | None:
    import tempus_ddb

    for name in _CORE_PARSER_NAMES:
        candidate = getattr(tempus_ddb, name, None)
        if callable(candidate):
            return candidate
    return None


def _reject_duplicate_keys(pairs: list[tuple[Any, Any]]) -> dict[Any, Any]:
    obj: dict[Any, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise json.JSONDecodeError(
                f"{DUPLICATE_JSON_KEY}: object key {key!r} appears more than once",
                "",
                0,
            )
        obj[key] = value
    return obj


def loads(payload: str | bytes | bytearray) -> Any:
    """Parse one JSON document, failing closed on a repeated object key at any depth."""
    if isinstance(payload, (bytes, bytearray)):
        text = payload.decode("utf-8")
    else:
        text = payload
    parser = _core_parser()
    if parser is not None:
        try:
            return parser(text)
        except json.JSONDecodeError:
            raise
        except ValueError as exc:
            raise json.JSONDecodeError(str(exc), "", 0) from exc
    # TODO: remove this minimal object_pairs_hook when tempus_ddb.strict_loads is public.
    # https://github.com/Julio-Patron/tempus-ddb/issues/86
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
