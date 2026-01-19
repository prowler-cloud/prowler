"""Base models and mixins for Prowler MCP Server models."""

from typing import Any

from pydantic import BaseModel, SerializerFunctionWrapHandler, model_serializer


class MinimalSerializerMixin(BaseModel):
    """Mixin that excludes empty values from serialization.

    This mixin optimizes model serialization for LLM consumption by removing noise
    and reducing token usage. It excludes:
    - None values
    - Empty strings
    - Empty lists
    - Empty dicts
    """

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """Serialize model excluding empty values.

        Args:
            handler: Pydantic serializer function wrapper

        Returns:
            Dictionary with non-empty values only
        """
        data = handler(self)
        return {k: v for k, v in data.items() if not self._should_exclude(k, v)}

    def _should_exclude(self, key: str, value: Any) -> bool:
        """Determine if a key-value pair should be excluded from serialization.

        Override this method in subclasses for custom exclusion logic.

        Args:
            key: Field name
            value: Field value

        Returns:
            True if the field should be excluded, False otherwise
        """
        # None values
        if value is None:
            return True

        # Empty strings
        if value == "":
            return True

        # Empty lists
        if isinstance(value, list) and not value:
            return True

        # Empty dicts
        if isinstance(value, dict) and not value:
            return True

        return False
