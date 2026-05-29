from typing import Optional
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.service import OktaService


def _next_after_cursor(resp) -> Optional[str]:
    """Extract the `after` cursor from a `Link: ...; rel="next"` header.

    Returns None when there is no next page. Header format follows RFC 5988
    and Okta's pagination guide.
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
    "global_session_policies": "okta.policies.read",
    "sign_in_pages": "okta.brands.read",
}


class Signon(OktaService):
    """Fetches OKTA_SIGN_ON policies, rules, and brand sign-in pages.

    Populates `self.global_session_policies` keyed by policy id. Each
    policy carries its rules; downstream checks read directly from this
    structure.

    Also populates `self.sign_in_pages` keyed by brand id with sign-in page
    HTML used by the DOD warning-banner check. When a brand has no
    customized page, the service falls back to the default sign-in page
    exposed by the Okta Management API and tracks it with
    `is_customized=False`.

    Before each fetch the service compares its required OAuth scope
    (see `REQUIRED_SCOPES`) against the access token's granted scopes
    (`provider.identity.granted_scopes`). When a scope is known to be
    missing, the fetch is skipped and the resource is recorded in
    `self.missing_scope` so checks can report the missing scope explicitly
    instead of emitting a misleading "no resources returned" finding.
    When granted_scopes is empty (token decode unavailable), the service
    treats permissions as unknown and attempts the fetch — preserving
    the prior behavior.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        granted = set(getattr(provider.identity, "granted_scopes", None) or [])
        self.missing_scope: dict[str, Optional[str]] = {
            resource: (scope if granted and scope not in granted else None)
            for resource, scope in REQUIRED_SCOPES.items()
        }

        self.global_session_policies: dict[str, GlobalSessionPolicy] = (
            {}
            if self.missing_scope["global_session_policies"]
            else self._list_global_session_policies()
        )
        self.sign_in_pages: dict[str, SignInPage] = (
            {} if self.missing_scope["sign_in_pages"] else self._list_sign_in_pages()
        )

    def _list_global_session_policies(self) -> dict:
        logger.info("Signon - Listing OKTA_SIGN_ON policies and rules...")
        try:
            return self._run(self._fetch_all())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_all(self) -> dict:
        result: dict[str, GlobalSessionPolicy] = {}
        all_policies, err = await self._paginate(
            lambda after: self.client.list_policies(type="OKTA_SIGN_ON", after=after)
        )
        if err is not None:
            logger.error(f"Error listing OKTA_SIGN_ON policies: {err}")
            return result

        for policy in all_policies:
            rules = await self._fetch_rules(policy.id)
            result[policy.id] = GlobalSessionPolicy(
                id=policy.id,
                name=getattr(policy, "name", "") or "",
                priority=getattr(policy, "priority", None),
                status=getattr(policy, "status", "") or "",
                is_default=bool(getattr(policy, "system", False)),
                rules=rules,
            )
        return result

    async def _fetch_rules(self, policy_id: str) -> list:
        # Okta's `list_policy_rules` endpoint does not expose an `after`
        # cursor in the SDK signature, so we call once with a generous
        # `limit`. Tenants with more rules per policy than the limit would
        # silently truncate; this is rare (most policies have <10 rules).
        rule_fetch_limit = 100
        rules_out: list[GlobalSessionPolicyRule] = []
        result = await self.client.list_policy_rules(
            policy_id, limit=str(rule_fetch_limit)
        )
        err = result[-1]
        if err is not None:
            logger.error(f"Error listing rules for policy {policy_id}: {err}")
            return rules_out
        all_rules = list(result[0] or [])
        if len(all_rules) >= rule_fetch_limit:
            logger.warning(
                f"Policy {policy_id} returned {len(all_rules)} rules — the "
                f"per-policy fetch limit ({rule_fetch_limit}) was hit; any "
                "rules beyond this limit are not evaluated by Prowler. "
                "Review the policy in the Okta Admin Console."
            )

        for rule in all_rules:
            actions = getattr(rule, "actions", None)
            signon = getattr(actions, "signon", None) if actions else None
            session = getattr(signon, "session", None) if signon else None
            conditions = getattr(rule, "conditions", None)
            network = getattr(conditions, "network", None) if conditions else None
            rules_out.append(
                GlobalSessionPolicyRule(
                    id=getattr(rule, "id", "") or "",
                    name=getattr(rule, "name", "") or "",
                    priority=getattr(rule, "priority", None),
                    status=getattr(rule, "status", "") or "",
                    is_default=bool(getattr(rule, "system", False)),
                    max_session_idle_minutes=getattr(
                        session, "max_session_idle_minutes", None
                    ),
                    max_session_lifetime_minutes=getattr(
                        session, "max_session_lifetime_minutes", None
                    ),
                    use_persistent_cookie=getattr(
                        session, "use_persistent_cookie", None
                    ),
                    network_zones_include=list(getattr(network, "include", None) or []),
                    network_zones_exclude=list(getattr(network, "exclude", None) or []),
                )
            )
        return rules_out

    def _list_sign_in_pages(self) -> dict:
        logger.info("Signon - Listing brand sign-in pages...")
        try:
            return self._run(self._fetch_brands_and_pages())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_brands_and_pages(self) -> dict:
        result: dict[str, SignInPage] = {}
        all_brands, err = await self._paginate(
            lambda after: self.client.list_brands(after=after)
        )
        if err is not None:
            logger.error(f"Error listing brands: {err}")
            return result

        for brand in all_brands:
            brand_id = getattr(brand, "id", "") or ""
            brand_name = getattr(brand, "name", "") or ""
            result[brand_id] = await self._fetch_sign_in_page(brand_id, brand_name)
        return result

    async def _fetch_sign_in_page(self, brand_id: str, brand_name: str) -> "SignInPage":
        page_result = await self.client.get_customized_sign_in_page(brand_id)
        page_err = page_result[-1]
        page_data = page_result[0]
        if page_err is None:
            return SignInPage(
                brand_id=brand_id,
                brand_name=brand_name,
                is_customized=True,
                page_content=getattr(page_data, "page_content", None),
            )

        if not self._is_missing_customized_page_error(page_err):
            return SignInPage(
                brand_id=brand_id,
                brand_name=brand_name,
                is_customized=False,
                fetch_error=str(page_err),
            )

        default_page_result = await self.client.get_default_sign_in_page(brand_id)
        default_page_err = default_page_result[-1]
        default_page_data = default_page_result[0]
        if default_page_err is not None:
            return SignInPage(
                brand_id=brand_id,
                brand_name=brand_name,
                is_customized=False,
                fetch_error=str(default_page_err),
            )

        return SignInPage(
            brand_id=brand_id,
            brand_name=brand_name,
            is_customized=False,
            page_content=getattr(default_page_data, "page_content", None),
        )

    @staticmethod
    def _is_missing_customized_page_error(error) -> bool:
        err_text = str(error).lower()
        return "404" in err_text or "not found" in err_text or "e0000007" in err_text

    @staticmethod
    async def _paginate(fetch):
        """Drain all pages of an SDK list call.

        `fetch` is a callable that takes the `after` cursor (or None for
        the first page) and returns the SDK's standard `(items, resp, err)`
        tuple. We follow `Link: rel="next"` headers until exhausted.
        """
        all_items = []
        result = await fetch(None)
        # Defensive against the SDK's 2-tuple early-error path: error is last.
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


class GlobalSessionPolicyRule(BaseModel):
    id: str
    name: str
    priority: Optional[int] = None
    status: str = ""
    is_default: bool = False
    max_session_idle_minutes: Optional[int] = None
    max_session_lifetime_minutes: Optional[int] = None
    use_persistent_cookie: Optional[bool] = None
    network_zones_include: list[str] = []
    network_zones_exclude: list[str] = []


class GlobalSessionPolicy(BaseModel):
    id: str
    name: str
    priority: Optional[int] = None
    status: str = ""
    is_default: bool = False
    rules: list[GlobalSessionPolicyRule] = []


class SignInPage(BaseModel):
    brand_id: str
    brand_name: str = ""
    is_customized: bool = False
    page_content: Optional[str] = None
    fetch_error: Optional[str] = None
