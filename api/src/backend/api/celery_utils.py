import ast
import json
from typing import Any

_UNPARSED = object()


def decode_celery_field(value: Any, default: Any) -> Any:
    """Decode a Celery result field and require JSON-serializable output."""
    decoded = value
    for _ in range(2):
        if not isinstance(decoded, str):
            break

        text = decoded.strip()
        if not text:
            decoded = default
            break

        parsed = _UNPARSED
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
                break
            except (TypeError, ValueError, SyntaxError):
                continue

        if parsed is _UNPARSED:
            raise ValueError("Unable to decode Celery result field")
        decoded = parsed

    decoded = default if decoded is None else decoded
    try:
        json.dumps(decoded, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Decoded Celery result field is not JSON serializable"
        ) from error

    return decoded
