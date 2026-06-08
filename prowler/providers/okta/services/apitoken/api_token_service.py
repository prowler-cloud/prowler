import json
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import BaseModel, Field, ValidationError

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService
from prowler.providers.okta.services.network.network_zone_service import (
    _next_after_cursor,
)

REQUIRED_SCOPES: dict[str, str] = {
    "api_tokens": "okta.apiTokens.read",
    "network_zones": "okta.networkZones.read",
    "user_roles": "okta.roles.read",
    # Needed to resolve admin roles inherited via group membership.
    # `/api/v1/users/{id}/roles` returns only direct role assignments;
    # group-inherited Super Admin is invisible without `okta.groups.read`
    # to enumerate the user's groups.
    "user_groups": "okta.groups.read",
}


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


def _role_to_string(role) -> str:
    """Pick the most specific role identifier from an SDK Role object.

    `list_assigned_roles_for_user` and `list_group_assigned_roles` return
    `ListGroupAssignedRoles200ResponseInner` — a oneOf wrapper that holds
    the real `StandardRole`/`CustomRole` on `.actual_instance`. Reading
    `.type`/`.label` from the wrapper returns None and the role silently
    disappears, so unwrap first.
    """
    inner = getattr(role, "actual_instance", None) or role
    return _value(getattr(inner, "type", None)) or _value(getattr(inner, "label", None))


class ApiToken(OktaService):
    """Fetches Okta API token metadata, token owners' roles, and zones."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        granted = set(getattr(provider.identity, "granted_scopes", None) or [])
        self.missing_scope: dict[str, Optional[str]] = {
            resource: (scope if granted and scope not in granted else None)
            for resource, scope in REQUIRED_SCOPES.items()
        }
        # Per-resource caches keyed on the Okta resource id. API tokens
        # commonly share owners (e.g. a service user holding multiple
        # tokens) and admin groups frequently overlap across users, so we
        # memoize the resolutions within a single service instance.
        self._user_roles_cache: dict[str, list[str]] = {}
        self._group_roles_cache: dict[str, list[str]] = {}
        self.known_network_zone_ids: set[str] = (
            set()
            if self.missing_scope["api_tokens"] or self.missing_scope["network_zones"]
            else self._list_known_network_zone_ids()
        )
        self.api_tokens: dict[str, OktaApiToken] = (
            {} if self.missing_scope["api_tokens"] else self._list_api_tokens()
        )

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
            roles = (
                await self._fetch_effective_user_role_types(user_id) if user_id else []
            )
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

    async def _fetch_effective_user_role_types(self, user_id: str) -> list[str]:
        """Return direct + group-inherited admin role types for `user_id`.

        Okta's `/api/v1/users/{userId}/roles` (the SDK's
        `list_assigned_roles_for_user`) only returns roles assigned
        *directly* to the user. Roles inherited via group membership are
        invisible to that endpoint — but they are how Okta normally
        grants Super Admin (e.g. the org creator joins the default
        "Okta Super Admins" group). Without resolving group-inherited
        roles, the Super Admin check would falsely PASS for any token
        whose owner gets admin via a group.

        Results are memoized per `user_id` so multiple tokens with the
        same owner cost a single resolution.
        """
        if user_id in self._user_roles_cache:
            return self._user_roles_cache[user_id]
        direct = await self._fetch_direct_user_role_types(user_id)
        inherited = await self._fetch_group_inherited_role_types(user_id)
        # Dedupe while preserving first-seen order (direct first, then
        # inherited) so the status_extended reads from most-specific.
        seen: set[str] = set()
        combined: list[str] = []
        for role in (*direct, *inherited):
            if role and role not in seen:
                combined.append(role)
                seen.add(role)
        self._user_roles_cache[user_id] = combined
        return combined

    async def _fetch_direct_user_role_types(self, user_id: str) -> list[str]:
        """Return roles assigned directly to the user (no group inheritance)."""
        if self.missing_scope["user_roles"]:
            return []
        items, _resp, err = _normalise_sdk_result(
            await self.client.list_assigned_roles_for_user(user_id)
        )
        if err is not None:
            logger.error(f"Error listing roles for token owner {user_id}: {err}")
            return []
        return [_role_to_string(role) for role in items if _role_to_string(role)]

    async def _fetch_group_inherited_role_types(self, user_id: str) -> list[str]:
        """Return roles inherited via the user's group memberships.

        Each group's role list is itself memoized — admin groups are
        commonly shared across many users.
        """
        if self.missing_scope["user_roles"] or self.missing_scope["user_groups"]:
            return []
        groups, _resp, err = _normalise_sdk_result(
            await self.client.list_user_groups(user_id)
        )
        if err is not None:
            logger.error(f"Error listing groups for token owner {user_id}: {err}")
            return []
        roles: list[str] = []
        for group in groups:
            group_id = _value(getattr(group, "id", None))
            if not group_id:
                continue
            if group_id in self._group_roles_cache:
                roles.extend(self._group_roles_cache[group_id])
                continue
            # Per-group try/except: one group's parse or auth failure
            # must not erase admin-role coverage for other groups.
            try:
                group_roles = await self._fetch_group_role_types(group_id)
            except Exception as error:
                logger.error(
                    f"Error listing roles for group {group_id} "
                    f"(owner={user_id}): {error.__class__.__name__}: {error}"
                )
                group_roles = []
            self._group_roles_cache[group_id] = group_roles
            roles.extend(group_roles)
        return roles

    async def _fetch_group_role_types(self, group_id: str) -> list[str]:
        """Return role types assigned to `group_id`."""
        items, _resp, err = _normalise_sdk_result(
            await self.client.list_group_assigned_roles(group_id)
        )
        if err is not None:
            logger.error(f"Error listing roles for group {group_id}: {err}")
            return []
        return [_role_to_string(role) for role in items if _role_to_string(role)]

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
        try:
            items, err = await self._fetch_all_network_zones()
        except ValidationError as ve:
            # Upstream Okta SDK ↔ Management API schema drift: the SDK
            # generates `EnhancedDynamicNetworkZoneAllOfAsnsInclude` as an
            # object-shaped pydantic model, but the API returns
            # `asns.include` as a JSON array (typically `[]`), so pydantic
            # rejects the whole zone list. Fall back to a raw-JSON fetch
            # so the API-token zone-restriction check isn't blocked by an
            # upstream SDK bug. Mirrors `application_service`'s raw
            # `list_policy_rules` fallback. Should be removed (and ideally
            # replaced with the shared `raw_fetch` helper introduced by
            # PR #11496) once upstream fixes the SDK.
            logger.warning(
                f"Okta SDK raised ValidationError parsing Network Zones "
                f"({ve.error_count()} error(s)) — falling back to raw-JSON "
                "parse for API token zone validation."
            )
            return await self._fetch_known_network_zone_ids_raw()
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
        return await self._paginate(
            lambda after: self.client.list_network_zones(after=after, limit=200)
        )

    async def _fetch_known_network_zone_ids_raw(self) -> set[str]:
        """Raw-JSON fallback for `list_network_zones`.

        Drains `/api/v1/zones?limit=200` via the SDK request executor,
        following the `Link: rel="next"` cursor across pages so the
        fallback doesn't silently truncate at the first page. Only the
        `id` and `name` fields are read — enough to populate the lookup
        set used by `apitoken_restricted_to_network_zone`.
        """
        identifiers: set[str] = set()
        current_path = _set_query("/api/v1/zones", {"limit": "200"})
        while True:
            request, error = await self.client._request_executor.create_request(
                method="GET",
                url=current_path,
                body=None,
                headers={"Accept": "application/json"},
            )
            if error is not None:
                logger.error(
                    f"Raw Network Zones fetch (create_request) failed: {error}"
                )
                return identifiers

            response, response_body, error = (
                await self.client._request_executor.execute(request)
            )
            if error is not None:
                logger.error(f"Raw Network Zones fetch (execute) failed: {error}")
                return identifiers

            if isinstance(response_body, (bytes, bytearray)):
                try:
                    response_body = response_body.decode("utf-8")
                except UnicodeDecodeError as decode_err:
                    logger.error(
                        f"Could not decode Network Zones response: {decode_err}"
                    )
                    return identifiers
            if not response_body:
                break
            try:
                zones_data = json.loads(response_body)
            except json.JSONDecodeError as decode_err:
                logger.error(f"Could not parse Network Zones JSON: {decode_err}")
                return identifiers

            if not isinstance(zones_data, list):
                logger.error(
                    f"Unexpected raw Network Zones payload shape: "
                    f"got {type(zones_data).__name__}, expected list"
                )
                return identifiers

            for zone_dict in zones_data:
                if not isinstance(zone_dict, dict):
                    continue
                zone_id = zone_dict.get("id")
                zone_name = zone_dict.get("name")
                if zone_id:
                    identifiers.add(str(zone_id))
                if zone_name:
                    identifiers.add(str(zone_name))

            cursor = _next_after_cursor(response)
            if not cursor:
                break
            # `_next_after_cursor` URL-decodes via `parse_qs`; `_set_query`
            # delegates to `urlencode`, which re-quotes the cursor so it
            # round-trips correctly through any opaque characters.
            current_path = _set_query(
                "/api/v1/zones", {"limit": "200", "after": cursor}
            )
        return identifiers

    @staticmethod
    async def _paginate(fetch) -> tuple[list, object]:
        """Drain all pages of an SDK list call using Okta Link cursors."""
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


def _set_query(path: str, params: dict) -> str:
    """Return `path` with the given query params merged in (overriding existing)."""
    parsed = urlparse(path)
    qs = dict(parse_qsl(parsed.query))
    qs.update({k: v for k, v in params.items() if v is not None})
    return urlunparse(parsed._replace(query=urlencode(qs)))


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
