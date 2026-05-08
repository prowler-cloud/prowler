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


class Signon(OktaService):
    """Fetches OKTA_SIGN_ON policies and their rules.

    Populates `self.global_session_policies` keyed by policy id. Each
    policy carries its rules; downstream checks read directly from this
    structure.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.global_session_policies: dict[str, GlobalSessionPolicy] = (
            self._list_global_session_policies()
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
        rules_out: list[GlobalSessionPolicyRule] = []
        result = await self.client.list_policy_rules(policy_id, limit="100")
        err = result[-1]
        if err is not None:
            logger.error(f"Error listing rules for policy {policy_id}: {err}")
            return rules_out
        all_rules = list(result[0] or [])

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
                    is_default=bool(getattr(rule, "system", False)),
                    max_session_idle_minutes=(
                        getattr(session, "max_session_idle_minutes", None)
                        if session
                        else None
                    ),
                    max_session_lifetime_minutes=(
                        getattr(session, "max_session_lifetime_minutes", None)
                        if session
                        else None
                    ),
                    use_persistent_cookie=(
                        getattr(session, "use_persistent_cookie", None)
                        if session
                        else None
                    ),
                    network_zones_include=list(getattr(network, "include", None) or []),
                    network_zones_exclude=list(getattr(network, "exclude", None) or []),
                )
            )
        return rules_out

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
    is_default: bool = False
    max_session_idle_minutes: Optional[int] = None
    max_session_lifetime_minutes: Optional[int] = None
    use_persistent_cookie: Optional[bool] = None
    network_zones_include: list[str] = []
    network_zones_exclude: list[str] = []


class GlobalSessionPolicy(BaseModel):
    id: str
    name: str
    status: str = ""
    is_default: bool = False
    rules: list[GlobalSessionPolicyRule] = []
