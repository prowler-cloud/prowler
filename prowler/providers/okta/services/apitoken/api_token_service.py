from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.services.network.network_zone_service import (
    _next_after_cursor,
)


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
        self.known_network_zone_ids: set[str] = self._list_known_network_zone_ids()
        self.api_tokens: dict[str, OktaApiToken] = self._list_api_tokens()

    def _list_api_tokens(self) -> dict[str, "OktaApiToken"]:
        """List active API token metadata and owner roles."""
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
