from typing import Optional
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService

API_TOKENS_READ_SCOPE = "okta.apiTokens.read"
NETWORK_ZONES_READ_SCOPE = "okta.networkZones.read"
ROLES_READ_SCOPE = "okta.roles.read"


def _next_after_cursor(resp) -> Optional[str]:
    """Extract the Okta pagination cursor from a Link header."""
    if resp is None:
        return None
    headers = getattr(resp, "headers", None) or {}
    link = headers.get("link") or headers.get("Link") or ""
    if not link:
        return None
    for part in link.split(","):
        if 'rel="next"' not in part:
            continue
        url_segment = part.split(";", 1)[0].strip().lstrip("<").rstrip(">")
        cursor = parse_qs(urlparse(url_segment).query).get("after", [None])[0]
        if cursor:
            return cursor
    return None


def _normalise_sdk_result(result) -> tuple[list, object, object]:
    """Return `(items, response, error)` for Okta SDK list call variants."""
    if isinstance(result, tuple):
        err = result[-1]
        items = result[0] or []
        resp = result[1] if len(result) >= 3 else None
        return list(items), resp, err
    return list(result or []), None, None


def _value(value) -> str:
    """Return plain string values from Okta SDK enums and raw strings."""
    if value is None:
        return ""
    enum_value = getattr(value, "value", None)
    if enum_value is not None:
        return str(enum_value)
    return str(value)


class ApiToken(OktaService):
    """Fetches Okta API token metadata, token owners' roles, and zones."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.missing_scopes: list[str] = self._missing_scopes(
            [API_TOKENS_READ_SCOPE, NETWORK_ZONES_READ_SCOPE, ROLES_READ_SCOPE]
        )
        self.known_network_zone_ids: set[str] = self._list_known_network_zone_ids()
        self.api_tokens: dict[str, OktaApiToken] = self._list_api_tokens()

    def _list_api_tokens(self) -> dict[str, "OktaApiToken"]:
        """List active API token metadata and owner roles."""
        if API_TOKENS_READ_SCOPE in self.missing_scopes:
            logger.warning(
                "ApiToken - Skipping API Tokens API call because required "
                f"scope is missing: {API_TOKENS_READ_SCOPE}"
            )
            return {}
        logger.info("ApiToken - Listing Okta API tokens...")
        try:
            return self._run(self._fetch_api_tokens())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_api_tokens(self) -> dict[str, "OktaApiToken"]:
        result: dict[str, OktaApiToken] = {}
        items, _resp, err = _normalise_sdk_result(await self.client.list_api_tokens())
        if err is not None:
            logger.error(f"Error listing API tokens: {err}")
            return result

        for token in items:
            token_id = _value(getattr(token, "id", None))
            user_id = _value(getattr(token, "user_id", None))
            roles = await self._fetch_user_role_types(user_id) if user_id else []
            network = getattr(token, "network", None)
            token_obj = OktaApiToken(
                id=token_id,
                name=_value(getattr(token, "name", None)) or token_id,
                client_name=_value(getattr(token, "client_name", None)),
                user_id=user_id,
                network_connection=_value(getattr(network, "connection", None)),
                network_includes=list(getattr(network, "include", None) or []),
                network_excludes=list(getattr(network, "exclude", None) or []),
                owner_roles=roles,
            )
            result[token_obj.id] = token_obj
        return result

    async def _fetch_user_role_types(self, user_id: str) -> list[str]:
        """Return normalized admin role types assigned to the token owner."""
        if ROLES_READ_SCOPE in self.missing_scopes:
            logger.warning(
                "ApiToken - Skipping assigned role lookup for token owner "
                f"{user_id} because required scope is missing: {ROLES_READ_SCOPE}"
            )
            return []
        items, _resp, err = _normalise_sdk_result(
            await self.client.list_assigned_roles_for_user(user_id)
        )
        if err is not None:
            logger.error(f"Error listing roles for token owner {user_id}: {err}")
            return []
        roles = []
        for role in items:
            role_type = _value(getattr(role, "type", None))
            role_label = _value(getattr(role, "label", None))
            roles.append(role_type or role_label)
        return [role for role in roles if role]

    def _list_known_network_zone_ids(self) -> set[str]:
        """List known Network Zone ids and names for token condition validation."""
        if API_TOKENS_READ_SCOPE in self.missing_scopes:
            logger.warning(
                "ApiToken - Skipping Network Zones API call because API token "
                f"listing is unavailable without {API_TOKENS_READ_SCOPE}."
            )
            return set()
        if NETWORK_ZONES_READ_SCOPE in self.missing_scopes:
            logger.warning(
                "ApiToken - Skipping Network Zones API call because required "
                f"scope is missing: {NETWORK_ZONES_READ_SCOPE}"
            )
            return set()
        logger.info("ApiToken - Listing Network Zones for token restrictions...")
        try:
            return self._run(self._fetch_known_network_zone_ids())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return set()

    async def _fetch_known_network_zone_ids(self) -> set[str]:
        identifiers: set[str] = set()
        items, err = await self._fetch_all_network_zones()
        if err is not None:
            logger.error(f"Error listing Network Zones for API token checks: {err}")
            return identifiers
        for zone in items:
            zone_id = _value(getattr(zone, "id", None))
            zone_name = _value(getattr(zone, "name", None))
            if zone_id:
                identifiers.add(zone_id)
            if zone_name:
                identifiers.add(zone_name)
        return identifiers

    async def _fetch_all_network_zones(self) -> tuple[list, object]:
        """Drain all Network Zone pages for API token reference validation."""
        all_items = []
        result = await self.client.list_network_zones(after=None, limit=200)
        items, resp, err = _normalise_sdk_result(result)
        if err is not None:
            return [], err
        all_items.extend(items)
        while True:
            cursor = _next_after_cursor(resp)
            if not cursor:
                break
            result = await self.client.list_network_zones(after=cursor, limit=200)
            items, resp, err = _normalise_sdk_result(result)
            if err is not None:
                return all_items, err
            all_items.extend(items)
        return all_items, None


class OktaApiToken(BaseModel):
    """Normalized Okta API token metadata used by checks."""

    id: str
    name: str
    client_name: str = ""
    user_id: str = ""
    network_connection: str = ""
    network_includes: list[str] = Field(default_factory=list)
    network_excludes: list[str] = Field(default_factory=list)
    owner_roles: list[str] = Field(default_factory=list)


class ApiTokenSummary(BaseModel):
    """Synthetic resource for org-level API token findings."""

    id: str = "okta-api-tokens"
    name: str = "Okta API Tokens"
