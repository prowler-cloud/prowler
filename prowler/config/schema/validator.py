from typing import Any

from pydantic import ValidationError

from prowler.config.schema.base import ProviderConfigBase
from prowler.lib.logger import logger


def validate_provider_config(
    provider: str,
    raw: Any,
    schema_cls: type[ProviderConfigBase] | None,
) -> dict:
    """Validate a provider's config dict against its Pydantic schema.

    Behavior is intentionally lenient to preserve backwards compatibility:

    - If ``raw`` is not a dict, return an empty dict (mirrors prior loader).
    - If no schema is registered for ``provider``, return ``raw`` untouched.
    - On validation errors, log one WARNING per offending field, DROP those
      keys from the result, and continue. Consumers fall back to their own
      hard-coded defaults via ``audit_config.get(key, default)``.
    - Coerced values (e.g. ``"180"`` -> ``180``) replace the user's input
      so that downstream checks never receive a wrongly-typed value.
    """
    if not isinstance(raw, dict):
        return {}

    if schema_cls is None:
        return raw

    try:
        model = schema_cls.model_validate(raw)
        return model.model_dump(exclude_unset=True)
    except ValidationError as exc:
        bad_keys: set[str] = set()
        for err in exc.errors():
            loc = err.get("loc") or ()
            if not loc:
                continue
            key = loc[0]
            if not isinstance(key, str):
                continue
            bad_keys.add(key)
            logger.warning(
                f"prowler.config[{provider}.{key}] = {raw.get(key)!r} is invalid "
                f"({err.get('msg', 'validation error')}); the value will be ignored "
                f"and the built-in default will be used."
            )

        cleaned = {k: v for k, v in raw.items() if k not in bad_keys}
        try:
            model = schema_cls.model_validate(cleaned)
            return model.model_dump(exclude_unset=True)
        except ValidationError as exc2:
            logger.error(
                f"prowler.config[{provider}] could not be revalidated after dropping "
                f"invalid keys ({bad_keys}); passing through the cleaned dict as-is. "
                f"Underlying errors: {exc2.errors()}"
            )
            return cleaned
