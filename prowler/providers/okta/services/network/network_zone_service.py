from typing import Optional

from pydantic import BaseModel, Field, ValidationError

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.pagination import paginate as _paginate_shared
from prowler.providers.okta.lib.service.raw_fetch import (
    get_json_paginated as _raw_get_json_paginated,
)
from prowler.providers.okta.lib.service.service import OktaService

REQUIRED_SCOPES: dict[str, str] = {
    "network_zones": "okta.networkZones.read",
}


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
        self.retrieval_error: str | None = None
        self.network_zones: dict[str, OktaNetworkZone] = (
            {} if self.missing_scope["network_zones"] else self._list_network_zones()
        )

    def _set_retrieval_error(self, message: str) -> None:
        self.retrieval_error = message
        logger.error(message)

    def _list_network_zones(self) -> dict[str, "OktaNetworkZone"]:
        """List all Network Zones visible to the configured Okta service app."""
        logger.info("NetworkZone - Listing Okta Network Zones...")
        try:
            return self._run(self._fetch_all())
        except Exception as error:
            line_number = getattr(error.__traceback__, "tb_lineno", "unknown")
            self._set_retrieval_error(
                f"{error.__class__.__name__}[{line_number}]: {error}"
            )
            return {}

    async def _fetch_all(self) -> dict[str, "OktaNetworkZone"]:
        result: dict[str, OktaNetworkZone] = {}
        try:
            all_zones, err = await _paginate_shared(
                lambda after: self.client.list_network_zones(after=after, limit=200)
            )
        except (ValueError, ValidationError) as ex:
            # Upstream Okta SDK ↔ Management API schema drift: the SDK
            # generates `EnhancedDynamicNetworkZoneAllOfAsnsInclude` as an
            # object-shaped pydantic model, but the API returns
            # `asns.include` as a JSON array (typically `[]`), so pydantic
            # rejects the whole zone with `model_type` errors. Fall back
            # to a raw-JSON fetch so STIG evaluation isn't blocked by an
            # upstream SDK bug. Same workaround shape as
            # `application_service._fetch_access_policy_raw`. The wider
            # `(ValueError, ValidationError)` catch matches the
            # `user_service` precedent — the SDK raises either depending
            # on whether the failure is a discriminator miss or a model
            # mismatch.
            logger.warning(
                f"Okta SDK raised {type(ex).__name__} parsing Network Zones — "
                "falling back to raw-JSON parse. This is an okta-sdk-python "
                "deserialization bug; the workaround should be removed once "
                "upstream fixes it."
            )
            return await self._fetch_all_raw()
        if err is not None:
            self._set_retrieval_error(f"Error listing Network Zones: {err}")
            return result

        for zone in all_zones:
            zone_obj = self._build_zone(zone)
            result[zone_obj.id] = zone_obj
        return result

    async def _fetch_all_raw(self) -> dict[str, "OktaNetworkZone"]:
        """Raw-JSON fallback for `list_network_zones`.

        Bypasses the SDK's typed deserialization via the shared
        `get_json_paginated` helper, then projects each zone onto our
        own pydantic snapshot — which only validates the fields the
        STIG checks actually read.
        """
        result: dict[str, OktaNetworkZone] = {}
        zones_data = await _raw_get_json_paginated(
            self.client,
            "/api/v1/zones",
            page_size=200,
            context="Network Zones",
        )
        if zones_data is None:
            self._set_retrieval_error(
                "Raw Network Zones fetch failed; see logs for details."
            )
            return result
        for zone_dict in zones_data:
            if not isinstance(zone_dict, dict):
                continue
            zone_obj = _raw_zone_to_model(zone_dict)
            result[zone_obj.id] = zone_obj
        return result

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
            gateways=_address_values(getattr(zone, "gateways", None)),
            proxies=_address_values(getattr(zone, "proxies", None)),
            asns=_condition_values(getattr(zone, "asns", None)),
            locations=_condition_values(getattr(zone, "locations", None)),
            ip_service_categories=_condition_values(
                getattr(zone, "ip_service_categories", None)
            ),
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
    categories = _condition_values(zone_dict.get("ipServiceCategories"))
    # IP-typed zones return `gateways`/`proxies` as `[{type, value}]`
    # arrays; Enhanced Dynamic Zones return `asns`/`locations` and
    # `ipServiceCategories` as `{include, exclude}` objects. Keep the
    # `list[str]` shape by extracting address values and included
    # condition values from both SDK models and raw JSON.
    return OktaNetworkZone(
        id=zone_id,
        name=str(zone_dict.get("name") or zone_id),
        status=str(zone_dict.get("status") or ""),
        type=str(zone_dict.get("type") or ""),
        usage=str(zone_dict.get("usage") or ""),
        system=bool(zone_dict.get("system", False)),
        gateways=_address_values(zone_dict.get("gateways")),
        proxies=_address_values(zone_dict.get("proxies")),
        asns=_condition_values(zone_dict.get("asns")),
        locations=_condition_values(zone_dict.get("locations")),
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
        elif entry is not None:
            value = getattr(entry, "value", entry)
        else:
            value = None
        if value is not None:
            out.append(_value(value))
    return out


def _condition_values(raw) -> list[str]:
    """Return string values from Okta include/exclude-style conditions."""
    if raw is None:
        return []
    values = (
        raw.get("include") if isinstance(raw, dict) else getattr(raw, "include", raw)
    )
    if values is None:
        return []
    if not isinstance(values, list):
        values = [values]
    normalized = []
    for value in values:
        if isinstance(value, dict):
            value = value.get("value")
        if value is not None:
            normalized.append(_value(value))
    return normalized


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
