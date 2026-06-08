import json
from typing import Optional
from urllib.parse import parse_qs, quote, urlparse

from pydantic import BaseModel, Field, ValidationError

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService

REQUIRED_SCOPES: dict[str, str] = {
    "network_zones": "okta.networkZones.read",
}


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
        granted = set(getattr(provider.identity, "granted_scopes", None) or [])
        self.missing_scope: dict[str, Optional[str]] = {
            resource: (scope if granted and scope not in granted else None)
            for resource, scope in REQUIRED_SCOPES.items()
        }
        self.network_zones: dict[str, OktaNetworkZone] = (
            {} if self.missing_scope["network_zones"] else self._list_network_zones()
        )

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
        try:
            all_zones, err = await self._paginate(
                lambda after: self.client.list_network_zones(after=after, limit=200)
            )
        except ValidationError as ve:
            # Upstream Okta SDK ↔ Management API schema drift: the SDK
            # generates `EnhancedDynamicNetworkZoneAllOfAsnsInclude` as an
            # object-shaped pydantic model, but the API returns
            # `asns.include` as a JSON array (typically `[]`), so pydantic
            # rejects the whole zone with `model_type` errors. Fall back
            # to a raw-JSON fetch so STIG evaluation isn't blocked by an
            # upstream SDK bug. Same workaround shape as
            # `application_service._fetch_access_policy_raw`.
            logger.warning(
                f"Okta SDK raised ValidationError parsing Network Zones "
                f"({ve.error_count()} error(s)) — falling back to raw-JSON "
                "parse. This is an okta-sdk-python deserialization bug; the "
                "workaround should be removed once upstream fixes it."
            )
            return await self._fetch_all_raw()
        if err is not None:
            logger.error(f"Error listing Network Zones: {err}")
            return result

        for zone in all_zones:
            zone_obj = self._build_zone(zone)
            result[zone_obj.id] = zone_obj
        return result

    async def _fetch_all_raw(self) -> dict[str, "OktaNetworkZone"]:
        """Raw-JSON fallback for `list_network_zones`.

        Bypasses the Okta SDK's typed deserialization by calling the
        request executor directly without a response type. The response
        body is `json.loads`-ed and projected onto our own pydantic
        snapshot, which only validates the fields the STIG checks read.
        """
        result: dict[str, OktaNetworkZone] = {}
        after: Optional[str] = None
        while True:
            # `_next_after_cursor` URL-decodes via `parse_qs`, so re-encode
            # before re-inserting to round-trip any special characters in
            # the opaque cursor (e.g. `=`, `+`).
            query = "limit=200" + (f"&after={quote(after, safe='')}" if after else "")
            request, error = await self.client._request_executor.create_request(
                method="GET",
                url=f"/api/v1/zones?{query}",
                body=None,
                headers={"Accept": "application/json"},
            )
            if error is not None:
                logger.error(
                    f"Raw Network Zones fetch (create_request) failed: {error}"
                )
                return result

            response, response_body, error = (
                await self.client._request_executor.execute(request)
            )
            if error is not None:
                logger.error(f"Raw Network Zones fetch (execute) failed: {error}")
                return result

            if isinstance(response_body, (bytes, bytearray)):
                try:
                    response_body = response_body.decode("utf-8")
                except UnicodeDecodeError as decode_err:
                    logger.error(
                        f"Could not decode Network Zones response: {decode_err}"
                    )
                    return result
            try:
                zones_data = json.loads(response_body) if response_body else []
            except json.JSONDecodeError as decode_err:
                logger.error(f"Could not parse Network Zones JSON: {decode_err}")
                return result

            if not isinstance(zones_data, list):
                logger.error(
                    f"Unexpected raw Network Zones payload shape: "
                    f"got {type(zones_data).__name__}, expected list"
                )
                return result

            for zone_dict in zones_data:
                if not isinstance(zone_dict, dict):
                    continue
                zone_obj = _raw_zone_to_model(zone_dict)
                result[zone_obj.id] = zone_obj

            after = _next_after_cursor(response)
            if not after:
                break
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


def _raw_zone_to_model(zone_dict: dict) -> "OktaNetworkZone":
    """Project a raw `/api/v1/zones` JSON zone onto our model.

    Mirrors `NetworkZone._build_zone` but reads camelCase JSON keys
    (`ipServiceCategories`) instead of the SDK's snake_case attributes.
    Used by the raw-JSON fallback that activates when the Okta SDK's
    strict pydantic validators reject zone payloads the Management API
    returns (e.g. Enhanced Dynamic Zones with `asns.include: []`).
    """
    zone_id = str(zone_dict.get("id") or "")
    raw_categories = zone_dict.get("ipServiceCategories") or []
    categories: list[str] = []
    if isinstance(raw_categories, list):
        for entry in raw_categories:
            if isinstance(entry, dict):
                value = entry.get("value")
                if value is not None:
                    categories.append(str(value))
            elif entry is not None:
                categories.append(str(entry))
    # IP-typed zones return `gateways`/`proxies` as `[{type, value}]`
    # arrays; Enhanced Dynamic Zones return `asns`/`locations` as
    # `{include, exclude}` objects, not lists. The STIG checks only need
    # to know whether IP-zone gateway/proxy entries exist, so we keep
    # the `list[str]` shape by extracting each entry's `value` and
    # normalizing non-list payloads to `[]`.
    return OktaNetworkZone(
        id=zone_id,
        name=str(zone_dict.get("name") or zone_id),
        status=str(zone_dict.get("status") or ""),
        type=str(zone_dict.get("type") or ""),
        usage=str(zone_dict.get("usage") or ""),
        system=bool(zone_dict.get("system", False)),
        gateways=_address_values(zone_dict.get("gateways")),
        proxies=_address_values(zone_dict.get("proxies")),
        asns=_address_values(zone_dict.get("asns")),
        locations=_address_values(zone_dict.get("locations")),
        ip_service_categories=categories,
    )


def _address_values(raw) -> list[str]:
    """Return string values from an Okta address-style JSON array.

    Each entry in `gateways`/`proxies` is `{"type": ..., "value": ...}`;
    `asns`/`locations` may be a `{include, exclude}` object on Enhanced
    Dynamic Zones. Non-list inputs collapse to `[]` so the resulting
    list satisfies the pydantic `list[str]` field.
    """
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for entry in raw:
        if isinstance(entry, dict):
            value = entry.get("value")
            if value is not None:
                out.append(str(value))
        elif entry is not None:
            out.append(str(entry))
    return out


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
