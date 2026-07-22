from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

# Item type for excluded_checks / excluded_services list entries. Item
# whitespace is stripped via ``str_strip_whitespace`` on the base
# ``model_config`` (no second stripping implementation added here), so
# ``min_length=1`` catches "", "   ", and any all-whitespace input uniformly.
NonEmptyScopeIdentifier = Annotated[str, StringConstraints(min_length=1)]


class ProviderConfigBase(BaseModel):
    """Base for every provider config schema.

    ``extra="allow"`` is REQUIRED for backwards compatibility: third-party
    check plugins frequently introduce config keys we do not know about,
    and pre-existing user configs may carry deprecated keys. Validation
    must never reject these.
    """

    model_config = ConfigDict(
        extra="allow",
        str_strip_whitespace=True,
        validate_assignment=False,
    )

    excluded_checks: list[NonEmptyScopeIdentifier] = Field(
        default_factory=list,
        description="Check identifiers to exclude from the scan scope.",
        json_schema_extra={"default": [], "uniqueItems": True},
    )
    excluded_services: list[NonEmptyScopeIdentifier] = Field(
        default_factory=list,
        description="Service identifiers to exclude from the scan scope.",
        json_schema_extra={"default": [], "uniqueItems": True},
    )

    @field_validator("excluded_checks", "excluded_services")
    @classmethod
    def _reject_duplicates(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for item in value:
            if item in seen:
                duplicates.add(item)
            else:
                seen.add(item)
        if duplicates:
            raise ValueError(f"duplicate values are not allowed: {sorted(duplicates)}")
        return value
