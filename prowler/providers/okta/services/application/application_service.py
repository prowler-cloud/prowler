from typing import Optional
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService

# Canonical internal `name` values of the two OIN built-in apps the STIG
# targets. `label` is what the Admin Console displays, but `name` is the
# stable identifier returned by `/api/v1/apps` and is what we filter on.
ADMIN_CONSOLE_APP_NAME = "saasure"
DASHBOARD_APP_NAME = "okta_enduser"

# First-party app key used by Okta's `/api/v1/first-party-app-settings/{appName}`
# endpoint. Only `admin-console` is supported by Okta today.
ADMIN_CONSOLE_FIRST_PARTY_APP_KEY = "admin-console"


def _next_after_cursor(resp) -> Optional[str]:
    """Extract the `after` cursor from a `Link: ...; rel="next"` header.

    Returns None when there is no next page. Header format follows RFC 5988
    and Okta's pagination guide. Mirrors the helper in `signon_service` —
    duplicated rather than shared until a third Okta service appears.
    """
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


REQUIRED_SCOPES: dict[str, str] = {
    "admin_console_app_settings": "okta.apps.read",
    "built_in_apps": "okta.apps.read",
    "integrated_apps": "okta.apps.read",
    "access_policies": "okta.policies.read",
}


class Application(OktaService):
    """Fetches Okta first-party apps and their bound Authentication Policies.

    Populates:
    - `self.admin_console_app_settings` — first-party Admin Console session
      knobs (`sessionIdleTimeoutMinutes`, `sessionMaxLifetimeMinutes`).
    - `self.built_in_apps` — keyed by canonical `name` (`saasure`,
      `okta_enduser`). Each entry carries the resolved Authentication
      Policy (Access Policy) and its rules.
    - `self.integrated_apps` — lazily populated and keyed by application id.
      Used by the per-application network-zone STIG to evaluate every
      active app returned by `/api/v1/apps`.

    Required OAuth scopes (`REQUIRED_SCOPES`) are compared against the
    access token's granted scopes (`provider.identity.granted_scopes`).
    When a scope is known to be missing, the corresponding fetch is
    skipped and recorded in `self.missing_scope` so each check can emit
    an explicit MANUAL finding instead of a misleading
    "no resources returned". Empty granted_scopes means "unknown" — the
    service attempts the fetch and lets the SDK fail loudly.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        granted = set(getattr(provider.identity, "granted_scopes", None) or [])
        self.missing_scope: dict[str, Optional[str]] = {
            resource: (scope if granted and scope not in granted else None)
            for resource, scope in REQUIRED_SCOPES.items()
        }

        self.admin_console_app_settings: Optional[AdminConsoleAppSettings] = (
            None
            if self.missing_scope["admin_console_app_settings"]
            else self._get_admin_console_app_settings()
        )

        # Apps and policies share the same SDK round-trips, so fetch them
        # together. When either scope is missing we still attempt the
        # other, but `built_in_apps` is only populated when both are
        # available — checks then look at `missing_scope` to report which
        # one is at fault.
        if self.missing_scope["built_in_apps"] or self.missing_scope["access_policies"]:
            self.built_in_apps: dict[str, OktaBuiltInApp] = {}
        else:
            self.built_in_apps = self._list_built_in_apps_with_policies()
        self._integrated_apps: Optional[dict[str, OktaBuiltInApp]] = None

    @property
    def integrated_apps(self) -> dict[str, "OktaBuiltInApp"]:
        """List every Okta-integrated app with its Authentication Policy.

        This is fetched lazily because only the V-279693 check needs the
        full app inventory; the bundled Admin Console / Dashboard checks
        only need the two built-in apps.
        """
        if self._integrated_apps is None:
            if (
                self.missing_scope["integrated_apps"]
                or self.missing_scope["access_policies"]
            ):
                self._integrated_apps = {}
            else:
                self._integrated_apps = self._list_integrated_apps_with_policies()
        return self._integrated_apps

    def _get_admin_console_app_settings(self) -> Optional["AdminConsoleAppSettings"]:
        logger.info("Application - Fetching first-party Admin Console settings...")
        try:
            return self._run(self._fetch_admin_console_app_settings())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    async def _fetch_admin_console_app_settings(
        self,
    ) -> Optional["AdminConsoleAppSettings"]:
        result = await self.client.get_first_party_app_settings(
            ADMIN_CONSOLE_FIRST_PARTY_APP_KEY
        )
        err = result[-1]
        if err is not None:
            # 404 means the org is on Classic engine or the endpoint isn't
            # available — fall through to None and checks emit MANUAL.
            logger.error(f"Error fetching first-party Admin Console settings: {err}")
            return None
        data = result[0]
        if data is None:
            return None
        return AdminConsoleAppSettings(
            session_idle_timeout_minutes=getattr(
                data, "session_idle_timeout_minutes", None
            ),
            session_max_lifetime_minutes=getattr(
                data, "session_max_lifetime_minutes", None
            ),
        )

    def _list_built_in_apps_with_policies(self) -> dict:
        logger.info("Application - Listing Okta built-in apps and policies...")
        try:
            return self._run(self._fetch_built_in_apps_and_policies())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    def _list_integrated_apps_with_policies(self) -> dict:
        logger.info("Application - Listing integrated Okta apps and policies...")
        try:
            return self._run(self._fetch_integrated_apps_and_policies())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_built_in_apps_and_policies(self) -> dict:
        result: dict[str, OktaBuiltInApp] = {}
        for app_name in (ADMIN_CONSOLE_APP_NAME, DASHBOARD_APP_NAME):
            built_in_app = await self._fetch_built_in_app(app_name)
            if built_in_app is None:
                continue
            if built_in_app.access_policy_id:
                built_in_app.access_policy = await self._fetch_access_policy(
                    built_in_app.access_policy_id
                )
            result[app_name] = built_in_app
        return result

    async def _fetch_integrated_apps_and_policies(self) -> dict:
        all_apps, err = await self._paginate(
            lambda after: self.client.list_applications(after=after)
        )
        if err is not None:
            logger.error(f"Error listing integrated apps: {err}")
            return {}

        result: dict[str, OktaBuiltInApp] = {}
        for app in all_apps:
            app_model = _to_application_model(app)
            if app_model.access_policy_id:
                app_model.access_policy = await self._fetch_access_policy(
                    app_model.access_policy_id
                )
            result[app_model.id] = app_model
        return result

    async def _fetch_built_in_app(self, app_name: str) -> Optional["OktaBuiltInApp"]:
        # Filter by `name eq` so we don't paginate every app in the org
        # for a single match. The two OIN-built-in apps are uniquely
        # identified by their internal `name`.
        apps, err = await self._paginate(
            lambda after: self.client.list_applications(
                filter=f'name eq "{app_name}"', after=after
            )
        )
        if err is not None:
            logger.error(f"Error listing app with name={app_name}: {err}")
            return None
        if not apps:
            return None
        return _to_application_model(apps[0])

    async def _fetch_access_policy(
        self, policy_id: str
    ) -> Optional["AuthenticationPolicy"]:
        # Okta's `list_policy_rules` does not accept an `after` cursor in
        # the SDK signature, so we call once with a generous limit. Auth
        # policies almost always have <10 rules; a warning is logged if
        # the limit is hit.
        rule_fetch_limit = 100
        rules_out: list[AuthenticationPolicyRule] = []
        result = await self.client.list_policy_rules(
            policy_id, limit=str(rule_fetch_limit)
        )
        err = result[-1]
        if err is not None:
            logger.error(f"Error listing rules for access policy {policy_id}: {err}")
            return AuthenticationPolicy(
                id=policy_id,
                name="",
                status="",
                is_default=False,
                rules=[],
            )
        all_rules = list(result[0] or [])
        if len(all_rules) >= rule_fetch_limit:
            logger.warning(
                f"Access policy {policy_id} returned {len(all_rules)} rules — "
                f"the per-policy fetch limit ({rule_fetch_limit}) was hit; any "
                "rules beyond this limit are not evaluated by Prowler. Review "
                "the policy in the Okta Admin Console."
            )
        for rule in all_rules:
            rules_out.append(_rule_to_model(rule))
        return AuthenticationPolicy(
            id=policy_id,
            name="",
            status="",
            is_default=False,
            rules=rules_out,
        )

    @staticmethod
    async def _paginate(fetch):
        """Drain all pages of an SDK list call.

        `fetch` is a callable taking the `after` cursor (or None) and
        returning the SDK's `(items, resp, err)` tuple. Follows the
        `Link: rel="next"` header until exhausted. Mirrors the helper in
        `signon_service`.
        """
        all_items = []
        result = await fetch(None)
        err = result[-1]
        if err is not None:
            return [], err
        items = result[0]
        resp = result[1] if len(result) >= 3 else None
        all_items.extend(items or [])
        while True:
            cursor = _next_after_cursor(resp)
            if not cursor:
                break
            result = await fetch(cursor)
            err = result[-1]
            if err is not None:
                return all_items, err
            items = result[0]
            resp = result[1] if len(result) >= 3 else None
            all_items.extend(items or [])
        return all_items, None


def _policy_id_from_href(href: Optional[str]) -> Optional[str]:
    """Extract the trailing policy id from `.../policies/{id}` URLs."""
    if not href:
        return None
    path = urlparse(href).path or href
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    return segment or None


def _rule_to_model(rule) -> "AuthenticationPolicyRule":
    """Project an SDK `AccessPolicyRule` onto our pydantic snapshot.

    Pulls out the two STIG-relevant fields from the deeply nested
    `actions.appSignOn.verificationMethod` tree: the assurance `factor_mode`
    and whether any possession constraint requires phishing resistance.
    """
    actions = getattr(rule, "actions", None)
    app_sign_on = getattr(actions, "app_sign_on", None) if actions else None
    verification_method = (
        getattr(app_sign_on, "verification_method", None) if app_sign_on else None
    )
    factor_mode = _stringify_enum(getattr(verification_method, "factor_mode", None))
    verification_type = _stringify_enum(getattr(verification_method, "type", None))
    constraints = list(getattr(verification_method, "constraints", None) or [])
    phishing_resistant_required = False
    for constraint in constraints:
        possession = getattr(constraint, "possession", None)
        if possession is None:
            continue
        if (
            _stringify_enum(getattr(possession, "phishing_resistant", None))
            == "REQUIRED"
        ):
            phishing_resistant_required = True
            break

    access_action = getattr(app_sign_on, "access", None) if app_sign_on else None
    conditions = getattr(rule, "conditions", None)
    network = getattr(conditions, "network", None) if conditions else None
    return AuthenticationPolicyRule(
        id=getattr(rule, "id", "") or "",
        name=getattr(rule, "name", "") or "",
        priority=getattr(rule, "priority", None),
        status=getattr(rule, "status", "") or "",
        is_default=bool(getattr(rule, "system", False)),
        factor_mode=factor_mode,
        possession_phishing_resistant_required=phishing_resistant_required,
        constraints_count=len(constraints),
        verification_method_type=verification_type,
        access=_stringify_enum(access_action),
        network_connection=_stringify_enum(getattr(network, "connection", None)),
        network_zones_include=list(getattr(network, "include", None) or []),
        network_zones_exclude=list(getattr(network, "exclude", None) or []),
    )


def _stringify_enum(value) -> Optional[str]:
    """Return the string form of an enum-or-string value, or None."""
    if value is None:
        return None
    return getattr(value, "value", None) or str(value)


class AdminConsoleAppSettings(BaseModel):
    """First-party Okta Admin Console session settings.

    `id` and `name` are set to fixed sentinels so this can be passed as
    the `resource` to `CheckReportOkta`, which reads those attributes.
    """

    id: str = "okta-admin-console-app-settings"
    name: str = "Okta Admin Console (first-party app settings)"
    session_idle_timeout_minutes: Optional[int] = None
    session_max_lifetime_minutes: Optional[int] = None


class AuthenticationPolicyRule(BaseModel):
    id: str
    name: str
    priority: Optional[int] = None
    status: str = ""
    is_default: bool = False
    factor_mode: Optional[str] = None
    possession_phishing_resistant_required: bool = False
    constraints_count: int = 0
    verification_method_type: Optional[str] = None
    access: Optional[str] = None
    network_connection: Optional[str] = None
    network_zones_include: list[str] = []
    network_zones_exclude: list[str] = []


class AuthenticationPolicy(BaseModel):
    id: str
    name: str = ""
    status: str = ""
    is_default: bool = False
    rules: list[AuthenticationPolicyRule] = []


class OktaBuiltInApp(BaseModel):
    # `id` matches the Okta-generated `0oa…` app identifier; `name` is the
    # canonical internal name (`saasure`, `okta_enduser`). Both are read
    # directly by `CheckReportOkta(resource=…)`.
    id: str
    name: str
    label: str = ""
    status: str = ""
    access_policy_id: Optional[str] = None
    access_policy: Optional[AuthenticationPolicy] = None


def _application_access_policy_id(app) -> Optional[str]:
    links = getattr(app, "links", None)
    access_policy_link = getattr(links, "access_policy", None) if links else None
    return _policy_id_from_href(
        getattr(access_policy_link, "href", None) if access_policy_link else None
    )


def _to_application_model(app) -> OktaBuiltInApp:
    return OktaBuiltInApp(
        id=getattr(app, "id", "") or "",
        name=getattr(app, "name", "") or "",
        label=getattr(app, "label", "") or "",
        status=getattr(app, "status", "") or "",
        access_policy_id=_application_access_policy_id(app),
    )
