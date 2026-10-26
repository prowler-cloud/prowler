from typing import Any

REDACTED_VALUE = "REDACTED"


def _mask(value: Any) -> Any:
    """Replace every leaf of value with REDACTED_VALUE, keeping dict keys and list lengths."""
    if value is None or value == "" or value == [] or value == {}:
        return value
    if isinstance(value, dict):
        return {key: _mask(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask(item) for item in value]
    return REDACTED_VALUE


def redact_sensitive_fields(resource: Any, data: Any) -> Any:
    """Return data, the serialised form of resource, with the fields each model lists in sensitive_fields masked."""
    if isinstance(data, dict):
        if isinstance(resource, dict):
            return {
                key: redact_sensitive_fields(resource.get(key), item)
                for key, item in data.items()
            }
        sensitive = getattr(type(resource), "sensitive_fields", ())
        return {
            key: (
                _mask(item)
                if key in sensitive
                else redact_sensitive_fields(getattr(resource, key, None), item)
            )
            for key, item in data.items()
        }
    if (
        isinstance(data, list)
        and isinstance(resource, (list, tuple))
        and len(data) == len(resource)
    ):
        return [
            redact_sensitive_fields(item_resource, item)
            for item_resource, item in zip(resource, data)
        ]
    return data
