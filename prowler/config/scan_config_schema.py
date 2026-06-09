"""Bridge between the Pydantic-based provider schemas in
`prowler.config.schema` and the Prowler App backend (Django) + UI.

The SDK runtime is intentionally LENIENT: invalid keys are dropped with a
warning and downstream checks fall back to their defaults
(`prowler.config.schema.validator.validate_provider_config`).

The Prowler App, however, needs to surface those errors to the user when
they save a Scan Config from the UI, and to expose the schema as JSON so
the UI can validate live with `ajv`. This module provides:

- `validate_scan_config(payload)` — STRICT: returns a list of
  `{path, message}` errors without silently dropping anything. The DRF
  serializer (`api/.../v1/serializers.py:validate_scan_config_payload`)
  turns each entry into a `ValidationError`.

- `SCAN_CONFIG_SCHEMA` — aggregated JSON Schema derived from the Pydantic
  models via `model_json_schema()`. Served by the `/scan-configs/schema`
  endpoint and consumed by the UI editor for in-editor live validation.
"""

from typing import Any

from pydantic import ValidationError

from prowler.config.schema.registry import SCHEMAS


def _format_loc(loc: tuple) -> str:
    """Render a Pydantic error location as `key[idx].nested`."""
    parts: list[str] = []
    for piece in loc:
        if isinstance(piece, int):
            if parts:
                parts[-1] = f"{parts[-1]}[{piece}]"
            else:
                parts.append(f"[{piece}]")
        else:
            parts.append(str(piece))
    return ".".join(parts) if parts else "<root>"


def validate_scan_config(payload: Any) -> list[dict]:
    """Validate a scan config payload against the registered provider schemas.

    Strict by design: every Pydantic violation surfaces as a `{path, message}`
    entry so the caller can decide how to present it. Unknown provider
    sections are accepted (consistent with `additionalProperties: True` at
    the top level — the SDK simply has no opinion on them).
    """
    if not isinstance(payload, dict):
        return [
            {
                "path": "<root>",
                "message": "Scan config must be a mapping with provider sections.",
            }
        ]

    errors: list[dict] = []
    for provider, section in payload.items():
        schema_cls = SCHEMAS.get(provider)
        if schema_cls is None:
            # Unknown provider type: tolerated. The SDK will simply ignore it.
            continue
        if not isinstance(section, dict):
            errors.append(
                {
                    "path": str(provider),
                    "message": "section must be a mapping.",
                }
            )
            continue
        try:
            schema_cls.model_validate(section)
        except ValidationError as exc:
            for err in exc.errors():
                loc = err.get("loc") or ()
                path = _format_loc((str(provider), *loc))
                errors.append(
                    {
                        "path": path,
                        "message": err.get("msg", "validation error"),
                    }
                )
    return errors


def _build_aggregated_schema() -> dict:
    """Compose one JSON Schema per provider into a single top-level schema.

    The output mirrors the layout of `prowler/config/config.yaml` (a mapping
    keyed by provider type) and is what the UI consumes via `ajv`.
    """
    properties: dict[str, dict] = {}
    for provider, schema_cls in SCHEMAS.items():
        properties[provider] = schema_cls.model_json_schema()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Prowler Scan Config",
        "type": "object",
        "additionalProperties": True,
        "properties": properties,
    }


SCAN_CONFIG_SCHEMA: dict = _build_aggregated_schema()
