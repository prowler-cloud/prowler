from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.fly.lib.service.service import FlyService

APPS_IP_QUERY = """
query($slug: String!, $after: String) {
  organization(slug: $slug) {
    id
    slug
    apps(first: 100, after: $after) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        name
        sharedIpAddress
        ipAddresses(first: 100) {
          nodes {
            id
            address
            type
            region
          }
        }
      }
    }
  }
}
"""

# Fly.io places every app without an explicit network on the shared
# organization network, where all apps can reach each other over 6PN.
SHARED_NETWORK = "default"

# Flycast (private_v6) addresses are only reachable from the private network,
# so they never count as public exposure. Every 6PN address lives in fdaa::/16.
PRIVATE_IP_TYPES = {"private_v6"}
PRIVATE_IP_PREFIX = "fdaa:"
SHARED_IPV4_TYPE = "shared_v4"


def is_public_ip(ip: dict) -> bool:
    """Return whether an IP address node is a public (Anycast) address.

    Args:
        ip: An ``ipAddresses`` node from the Fly.io GraphQL API.

    Returns:
        bool: False for Flycast (``private_v6``, ``fdaa::/16``) addresses and
        empty entries, True otherwise.
    """
    address = str(ip.get("address") or "").lower()
    if not address or address.startswith(PRIVATE_IP_PREFIX):
        return False
    return str(ip.get("type") or "").lower() not in PRIVATE_IP_TYPES


class FlyIPAddress(BaseModel):
    """A public IP address allocated to a Fly.io app."""

    id: str
    address: str
    type: str
    region: str = "global"


class FlyApp(BaseModel):
    """A Fly.io app and its network exposure.

    ``network`` is ``None`` when the Machines API did not return the field, and
    ``public_ips`` is ``None`` when the public IP lookup did not succeed, so a
    check can report MANUAL instead of claiming compliance from a gap. Only
    public (Anycast) addresses are kept in ``public_ips``: dedicated IPv4/IPv6,
    plus the shared IPv4 Fly.io assigns to most apps.
    """

    id: str
    name: str
    org_slug: str
    network: Optional[str] = None
    region: str = "global"
    public_ips: Optional[list[FlyIPAddress]] = None

    @property
    def app_name(self) -> str:
        return self.name


class App(FlyService):
    """Retrieve Fly.io apps with their private network and public IP exposure."""

    def __init__(self, provider):
        super().__init__("App", provider)
        self.apps: dict[str, FlyApp] = {}
        self._list_apps()
        self._fetch_ip_addresses()

    def _list_apps(self):
        """List the apps of every organization in scope through the Machines API."""
        for org_slug in self.org_slugs:
            try:
                response = self._get("/apps", params={"org_slug": org_slug})
                if not response:
                    continue

                for app in response.get("apps", []) or []:
                    name = app.get("name")
                    if not name or not self._is_app_in_scope(name):
                        continue

                    # A missing or empty network field is kept as unknown; the
                    # check decides how to report it.
                    self.apps[name] = FlyApp(
                        id=app.get("id", name) or name,
                        name=name,
                        org_slug=org_slug,
                        network=app.get("network") or None,
                    )
            except Exception as error:
                logger.error(
                    f"{self.service} - Error listing apps for organization {org_slug}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _fetch_ip_addresses(self):
        """Attach the allocated public IP addresses to each app.

        Public IP allocation is only exposed by the Fly.io GraphQL API, so it is
        read there instead of through the Machines API, following the paginated
        ``apps`` connection to its end. Flycast (private IPv6) addresses are
        ignored, and the shared IPv4 exposed through the app's
        ``sharedIpAddress`` field is included, since it is reachable from the
        internet. Apps whose allocation could not be read, or that the lookup
        did not return, keep ``public_ips`` as ``None``.
        """
        for org_slug in self.org_slugs:
            try:
                after = None
                cursors = set()
                while True:
                    data = self._graphql(
                        APPS_IP_QUERY, {"slug": org_slug, "after": after}
                    )
                    apps = (data.get("organization") or {}).get("apps") or {}
                    for node in apps.get("nodes", []) or []:
                        app = self.apps.get(node.get("name") or "")
                        if app:
                            app.public_ips = self._public_ips(node)

                    page_info = apps.get("pageInfo") or {}
                    after = page_info.get("endCursor")
                    if (
                        not page_info.get("hasNextPage")
                        or not after
                        or after in cursors
                    ):
                        break
                    cursors.add(after)

                for app in self.apps.values():
                    if app.org_slug == org_slug and app.public_ips is None:
                        logger.warning(
                            f"{self.service} - App {app.name} was not returned by the "
                            f"Fly.io IP address lookup; its public IP allocation is "
                            f"unknown."
                        )
            except Exception as error:
                logger.error(
                    f"{self.service} - Error fetching IP addresses for organization {org_slug}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    @staticmethod
    def _public_ips(node: dict) -> list[FlyIPAddress]:
        """Build the public address list of an app node returned by GraphQL.

        Args:
            node: An ``apps`` node with ``ipAddresses`` and ``sharedIpAddress``.

        Returns:
            list[FlyIPAddress]: The dedicated public addresses plus the shared
            IPv4, without duplicates.
        """
        public_ips = [
            FlyIPAddress(
                id=ip.get("id") or "",
                address=ip.get("address") or "",
                type=ip.get("type") or "",
                region=ip.get("region") or "global",
            )
            for ip in (node.get("ipAddresses") or {}).get("nodes", []) or []
            if is_public_ip(ip)
        ]

        shared_ipv4 = node.get("sharedIpAddress")
        if shared_ipv4 and shared_ipv4 not in {ip.address for ip in public_ips}:
            public_ips.append(
                FlyIPAddress(
                    id="shared",
                    address=shared_ipv4,
                    type=SHARED_IPV4_TYPE,
                    region="global",
                )
            )

        return public_ips

    def get_app(self, name: str) -> Optional[FlyApp]:
        """Return an in-scope app by name."""
        return self.apps.get(name)
