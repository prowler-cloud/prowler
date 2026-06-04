from typing import Optional
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService


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


class NetworkZone(OktaService):
    """Fetches Okta Network Zones for STIG network-zone checks."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.network_zones: dict[str, OktaNetworkZone] = self._list_network_zones()

    def _list_network_zones(self) -> dict[str, "OktaNetworkZone"]:
        """List all Network Zones visible to the configured Okta service app."""
        logger.info("NetworkZone - Listing Okta Network Zones...")
        try:
            return self._run(self._fetch_all())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_all(self) -> dict[str, "OktaNetworkZone"]:
        result: dict[str, OktaNetworkZone] = {}
        all_zones, err = await self._paginate(
            lambda after: self.client.list_network_zones(after=after, limit=200)
        )
        if err is not None:
            logger.error(f"Error listing Network Zones: {err}")
            return result

        for zone in all_zones:
            zone_obj = self._build_zone(zone)
            result[zone_obj.id] = zone_obj
        return result

    @staticmethod
    async def _paginate(fetch):
        """Drain all pages of an SDK list call using Okta Link headers."""
        all_items = []
        result = await fetch(None)
        items, resp, err = _normalise_sdk_result(result)
        if err is not None:
            return [], err
        all_items.extend(items)
        while True:
            cursor = _next_after_cursor(resp)
            if not cursor:
                break
            result = await fetch(cursor)
            items, resp, err = _normalise_sdk_result(result)
            if err is not None:
                return all_items, err
            all_items.extend(items)
        return all_items, None

    @staticmethod
    def _build_zone(zone) -> "OktaNetworkZone":
        zone_id = _value(getattr(zone, "id", None))
        return OktaNetworkZone(
            id=zone_id,
            name=_value(getattr(zone, "name", None)) or zone_id,
            status=_value(getattr(zone, "status", None)),
            type=_value(getattr(zone, "type", None)),
            usage=_value(getattr(zone, "usage", None)),
            system=bool(getattr(zone, "system", False)),
            gateways=list(getattr(zone, "gateways", None) or []),
            proxies=list(getattr(zone, "proxies", None) or []),
            asns=list(getattr(zone, "asns", None) or []),
            locations=list(getattr(zone, "locations", None) or []),
            ip_service_categories=[
                _value(category)
                for category in (getattr(zone, "ip_service_categories", None) or [])
            ],
        )


class OktaNetworkZone(BaseModel):
    """Normalized Okta Network Zone attributes used by checks."""

    id: str
    name: str
    status: str = ""
    type: str = ""
    usage: str = ""
    system: bool = False
    gateways: list[str] = Field(default_factory=list)
    proxies: list[str] = Field(default_factory=list)
    asns: list[str] = Field(default_factory=list)
    locations: list[str] = Field(default_factory=list)
    ip_service_categories: list[str] = Field(default_factory=list)


class NetworkZoneSummary(BaseModel):
    """Synthetic resource for org-level Network Zone findings."""

    id: str = "okta-network-zones"
    name: str = "Okta Network Zones"
