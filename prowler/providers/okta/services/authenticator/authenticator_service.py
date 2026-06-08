from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.pagination import paginate as _paginate_shared
from prowler.providers.okta.lib.service.service import OktaService

REQUIRED_SCOPES: dict[str, str] = {
    "password_policies": "okta.policies.read",
    "authenticators": "okta.authenticators.read",
}


def _value(value) -> str:
    """Return plain string values from Okta SDK enums and raw strings."""
    if value is None:
        return ""
    enum_value = getattr(value, "value", None)
    if enum_value is not None:
        return str(enum_value)
    return str(value)


def _int_or_none(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool_or_none(value) -> Optional[bool]:
    """Coerce common Okta boolean shapes into a real `Optional[bool]`.

    The Okta SDK typed `bool` fields are already real booleans, but the
    raw-JSON fallback paths in sibling services have surfaced both
    JSON-style booleans (`true`/`false` as Python `bool` after `json.loads`)
    and string-flavored ones (`"true"`/`"false"`). `bool("false")` is
    `True` — so naive coercion silently flips the meaning. Reject that
    explicitly.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no", ""}:
            return False
        return None
    return bool(value)


class Authenticator(OktaService):
    """Fetches Okta Password Policies and Authenticators for STIG checks.

    Populates:
    - `self.password_policies` — keyed by policy id. Each `PasswordPolicy`
      carries the projected fields the 10 password-policy checks read
      (length, complexity, age, history, lockout, common-password
      dictionary). The complete typed SDK response is collapsed into a
      flat dataclass so the checks never reach back into the SDK shape.
    - `self.authenticators` — keyed by authenticator id. Used by the
      two non-password checks (Smart Card IdP, Okta Verify FIPS).

    Before each fetch the service compares its required OAuth scope
    (see `REQUIRED_SCOPES`) against the access token's granted scopes
    (`provider.identity.granted_scopes`). When a scope is known to be
    missing, the fetch is skipped and recorded in `self.missing_scope`
    so each check can emit an explicit MANUAL finding instead of a
    misleading "no resources returned". Empty granted_scopes means
    "unknown" — the service attempts the fetch and lets the SDK fail
    loudly.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        granted = set(getattr(provider.identity, "granted_scopes", None) or [])
        self.missing_scope: dict[str, Optional[str]] = {
            resource: (scope if granted and scope not in granted else None)
            for resource, scope in REQUIRED_SCOPES.items()
        }
        self.password_policies: dict[str, PasswordPolicy] = (
            {}
            if self.missing_scope["password_policies"]
            else self._list_password_policies()
        )
        self.authenticators: dict[str, OktaAuthenticator] = (
            {} if self.missing_scope["authenticators"] else self._list_authenticators()
        )

    def _list_password_policies(self) -> dict[str, "PasswordPolicy"]:
        """List PASSWORD policies with normalized password settings."""
        logger.info("Authenticator - Listing Okta PASSWORD policies...")
        try:
            return self._run(self._fetch_password_policies())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_password_policies(self) -> dict[str, "PasswordPolicy"]:
        result: dict[str, PasswordPolicy] = {}
        items, err = await _paginate_shared(
            lambda after: self.client.list_policies(
                type="PASSWORD", after=after, limit="200"
            )
        )
        if err is not None:
            logger.error(f"Error listing PASSWORD policies: {err}")
            return result

        for policy in items:
            policy_obj = self._build_password_policy(policy)
            result[policy_obj.id] = policy_obj
        return result

    def _list_authenticators(self) -> dict[str, "OktaAuthenticator"]:
        """List org authenticators with normalized settings."""
        logger.info("Authenticator - Listing Okta authenticators...")
        try:
            return self._run(self._fetch_authenticators())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_authenticators(self) -> dict[str, "OktaAuthenticator"]:
        # `list_authenticators` is non-paginated in the SDK (no `after`
        # parameter); inline the tuple unwrap rather than going through
        # `paginate`. Same shape `application_service` uses for
        # `get_first_party_app_settings`.
        result: dict[str, OktaAuthenticator] = {}
        sdk_result = await self.client.list_authenticators()
        err = sdk_result[-1]
        if err is not None:
            logger.error(f"Error listing authenticators: {err}")
            return result
        items = sdk_result[0] or []

        for authenticator in items:
            auth_obj = self._build_authenticator(authenticator)
            result[auth_obj.id] = auth_obj
        return result

    @staticmethod
    def _build_password_policy(policy) -> "PasswordPolicy":
        settings = getattr(policy, "settings", None)
        password_settings = getattr(settings, "password", None) if settings else None
        lockout = (
            getattr(password_settings, "lockout", None) if password_settings else None
        )
        complexity = (
            getattr(password_settings, "complexity", None)
            if password_settings
            else None
        )
        dictionary = getattr(complexity, "dictionary", None) if complexity else None
        common = getattr(dictionary, "common", None) if dictionary else None
        age = getattr(password_settings, "age", None) if password_settings else None
        policy_id = _value(getattr(policy, "id", None))
        return PasswordPolicy(
            id=policy_id,
            name=_value(getattr(policy, "name", None)) or policy_id,
            status=_value(getattr(policy, "status", None)),
            priority=_int_or_none(getattr(policy, "priority", None)),
            is_default=bool(getattr(policy, "system", False)),
            max_attempts=_int_or_none(getattr(lockout, "max_attempts", None)),
            min_length=_int_or_none(getattr(complexity, "min_length", None)),
            min_upper_case=_int_or_none(getattr(complexity, "min_upper_case", None)),
            min_lower_case=_int_or_none(getattr(complexity, "min_lower_case", None)),
            min_number=_int_or_none(getattr(complexity, "min_number", None)),
            min_symbol=_int_or_none(getattr(complexity, "min_symbol", None)),
            min_age_minutes=_int_or_none(getattr(age, "min_age_minutes", None)),
            max_age_days=_int_or_none(getattr(age, "max_age_days", None)),
            history_count=_int_or_none(getattr(age, "history_count", None)),
            common_password_check=_bool_or_none(getattr(common, "exclude", None)),
        )

    @staticmethod
    def _build_authenticator(authenticator) -> "OktaAuthenticator":
        settings = getattr(authenticator, "settings", None)
        compliance = getattr(settings, "compliance", None) if settings else None
        auth_id = _value(getattr(authenticator, "id", None))
        return OktaAuthenticator(
            id=auth_id,
            key=_value(getattr(authenticator, "key", None)),
            name=_value(getattr(authenticator, "name", None)) or auth_id,
            status=_value(getattr(authenticator, "status", None)),
            type=_value(getattr(authenticator, "type", None)),
            fips=_value(getattr(compliance, "fips", None)),
        )


class PasswordPolicy(BaseModel):
    """Normalized Okta Password Policy settings used by checks."""

    id: str
    name: str
    status: str = ""
    priority: Optional[int] = None
    is_default: bool = False
    max_attempts: Optional[int] = None
    min_length: Optional[int] = None
    min_upper_case: Optional[int] = None
    min_lower_case: Optional[int] = None
    min_number: Optional[int] = None
    min_symbol: Optional[int] = None
    min_age_minutes: Optional[int] = None
    max_age_days: Optional[int] = None
    history_count: Optional[int] = None
    common_password_check: Optional[bool] = None


class OktaAuthenticator(BaseModel):
    """Normalized Okta Authenticator settings used by checks."""

    id: str
    key: str
    name: str
    status: str = ""
    type: str = ""
    fips: str = ""


class AuthenticatorSummary(BaseModel):
    """Synthetic resource for org-level authenticator findings."""

    id: str
    name: str
