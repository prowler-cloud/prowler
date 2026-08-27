"""Bridge between the Pydantic-based provider schemas in
`prowler.config.schema` and the Prowler App backend (Django) + UI.

The SDK runtime is intentionally LENIENT: invalid keys are dropped with a
warning and downstream checks fall back to their defaults
(`prowler.config.schema.validator.validate_provider_config`).

The Prowler App, however, needs to surface those errors to the user when
they save a Scan Config from the UI, and to expose the schema as JSON so
the UI can validate live with `ajv`. This module provides:

- `validate_and_normalize_scan_config(payload)` — STRICT: returns
  ``(normalized, errors)``. When ``errors`` is non-empty the normalized
  dictionary is empty so callers never persist a partially validated
  configuration. On success the normalized payload is JSON-serializable
  (`model_dump(mode="json", exclude_unset=True)`), so the API can store
  it directly in a Django ``JSONField`` and consume it at scan time
  without re-running schema validation.

- `validate_scan_config(payload)` — thin backward-compatible wrapper that
  returns only the validation errors, preserved for callers that don't
  need the normalized payload.

- `SCAN_CONFIG_SCHEMA` — aggregated JSON Schema derived from the Pydantic
  models via `model_json_schema()`. Served by the `/scan-configs/schema`
  endpoint and consumed by the UI editor for in-editor live validation.
"""

import json
from functools import lru_cache
from typing import Any

from pydantic import ValidationError

from prowler.config.schema.registry import SCHEMAS
from prowler.lib.check.check import list_services
from prowler.lib.check.models import CheckMetadata

# Pydantic v2 prefixes messages emitted from a ``field_validator`` that
# raises ``ValueError`` with this string. Strip it so the message that
# reaches the UI is the one the validator actually wrote.
_PYDANTIC_VALUE_ERROR_PREFIX = "Value error, "


@lru_cache(maxsize=None)
def _get_provider_check_ids(provider: str) -> frozenset[str]:
    """Return cached check identifiers for a provider."""
    return frozenset(CheckMetadata.get_bulk(provider))


@lru_cache(maxsize=None)
def _get_provider_services(provider: str) -> frozenset[str]:
    """Return cached service identifiers for a provider."""
    return frozenset(list_services(provider))


def _format_loc(loc: tuple) -> str:
    """Render a Pydantic error location as a dot-separated path.

    Integer elements (array indices) are formatted as `[idx]` appended to the
    previous component. String elements are joined with dots. An empty location
    is rendered as `<root>`.

    Examples:
        ("aws", "regions", 0) -> "aws.regions[0]"
        ("aws", "threshold") -> "aws.threshold"
        () -> "<root>"
    """
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


def validate_and_normalize_scan_config(
    payload: Any,
) -> tuple[dict, list[dict[str, str]]]:
    """Strict validation and normalization of a scan configuration payload.

    Returns ``(normalized, errors)``:

    - ``normalized`` is a JSON-serializable dict that mirrors the layout of
      ``prowler/config/config.yaml`` (keyed by provider type). Registered
      provider sections are dumped from their Pydantic models with
      ``mode="json"`` (so the API can persist the result in a Django
      ``JSONField``) and ``exclude_unset=True`` (so omitted defaults are
      not injected into pre-existing configurations). Unknown provider
      sections and unknown keys inside registered sections are preserved
      untouched for forward compatibility with plugin-provided keys.
    - ``errors`` is a list of ``{"path": <dotted-path>, "message": <str>}``
      entries, one per schema or exclusion-catalog violation. When any error
      is present the normalized dictionary is returned empty so the caller
      never persists a partially validated configuration.

    The input payload is never mutated.
    """
    if not isinstance(payload, dict):
        return {}, [
            {
                "path": "<root>",
                "message": "Scan config must be a mapping with provider sections.",
            }
        ]

    errors: list[dict[str, str]] = []
    normalized: dict[str, Any] = {}

    for provider, section in payload.items():
        # Reject non-string provider keys so distinct entries like ``123``
        # and ``"123"`` don't collide after ``str()`` in the normalized dict.
        # YAML always produces string keys at this level; anything else
        # comes from a hand-built payload and is a caller bug.
        if not isinstance(provider, str):
            errors.append(
                {
                    "path": repr(provider),
                    "message": "provider keys must be strings.",
                }
            )
            continue

        provider_key = provider
        schema_cls = SCHEMAS.get(provider_key)
        if schema_cls is None:
            # Unknown provider type: tolerated, but only when its contents
            # are already JSON-serializable. The API persists the returned
            # payload in a Django ``JSONField`` and would blow up at write
            # time if we let a ``set()`` or similar through here.
            try:
                json.dumps(section)
            except (TypeError, ValueError) as exc:
                errors.append(
                    {
                        "path": provider_key,
                        "message": (
                            "unknown provider section is not JSON-serializable: "
                            f"{exc}"
                        ),
                    }
                )
                continue
            normalized[provider_key] = section
            continue
        if not isinstance(section, dict):
            errors.append(
                {
                    "path": provider_key,
                    "message": "section must be a mapping.",
                }
            )
            continue
        try:
            model = schema_cls.model_validate(section)
        except ValidationError as exc:
            for err in exc.errors():
                loc = err.get("loc") or ()
                path = _format_loc((provider_key, *loc))
                message = err.get("msg", "validation error")
                # Only strip on the specific error type that pydantic
                # prefixes — a legitimate future message that happens to
                # start with "Value error, " keeps its text intact.
                if err.get("type") == "value_error" and message.startswith(
                    _PYDANTIC_VALUE_ERROR_PREFIX
                ):
                    message = message[len(_PYDANTIC_VALUE_ERROR_PREFIX) :]
                errors.append({"path": path, "message": message})
            continue

        if model.excluded_checks:
            available_checks = _get_provider_check_ids(provider_key)
            for index, check in enumerate(model.excluded_checks):
                if check not in available_checks:
                    errors.append(
                        {
                            "path": f"{provider_key}.excluded_checks[{index}]",
                            "message": (
                                f"Unknown check '{check}' for provider "
                                f"'{provider_key}'."
                            ),
                        }
                    )

        if model.excluded_services:
            available_services = _get_provider_services(provider_key)
            for index, service in enumerate(model.excluded_services):
                if service not in available_services:
                    errors.append(
                        {
                            "path": f"{provider_key}.excluded_services[{index}]",
                            "message": (
                                f"Unknown service '{service}' for provider "
                                f"'{provider_key}'."
                            ),
                        }
                    )

        normalized[provider_key] = model.model_dump(mode="json", exclude_unset=True)

    if errors:
        return {}, errors
    return normalized, []


def validate_scan_config(payload: Any) -> list[dict]:
    """Backward-compatible wrapper returning only validation errors.

    Preserved for callers that only need the strict-validation error list
    (e.g. the DRF serializer that turns each entry into a
    ``ValidationError``). New callers should prefer
    :func:`validate_and_normalize_scan_config` to also receive the
    normalized payload.
    """
    _, errors = validate_and_normalize_scan_config(payload)
    return errors


def _build_aggregated_schema() -> dict:
    """Compose one JSON Schema per provider into a single top-level schema.

    The output mirrors the layout of `prowler/config/config.yaml` (a mapping
    keyed by provider type) and is what the UI consumes via `ajv`.

    Only app-facing providers (`sdk_only = False`, see
    `Provider.get_app_providers`) are included. SDK/CLI-only providers may
    still have a schema registered in `SCHEMAS` so the CLI validates their
    `config.yaml` (`load_and_validate_config_file` reads `SCHEMAS.get`), but
    they must not surface in this app-facing schema.
    """
    from prowler.providers.common.provider import Provider

    app_providers = set(Provider.get_app_providers())
    properties: dict[str, dict] = {}
    for provider, schema_cls in SCHEMAS.items():
        if provider not in app_providers:
            continue
        properties[provider] = schema_cls.model_json_schema()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Prowler Scan Config",
        "type": "object",
        "additionalProperties": True,
        "properties": properties,
    }


SCAN_CONFIG_SCHEMA: dict = _build_aggregated_schema()
