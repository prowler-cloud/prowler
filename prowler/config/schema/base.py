from pydantic import BaseModel, ConfigDict


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
