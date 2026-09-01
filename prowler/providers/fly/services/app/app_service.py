from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.fly.lib.service.service import FlyService

APPS_IP_QUERY = """
query($slug: String!) {
  organization(slug: $slug) {
    id
    slug
    apps {
      nodes {
        name
        ipAddresses {
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


class FlyIPAddress(BaseModel):
    """A public IP address allocated to a Fly.io app."""

    id: str
    address: str
    type: str
    region: str = "global"


class FlyApp(BaseModel):
    """A Fly.io app and its network exposure."""

    id: str
    name: str
    org_slug: str
    network: str = SHARED_NETWORK
    region: str = "global"
    public_ips: list[FlyIPAddress] = Field(default_factory=list)

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

                    self.apps[name] = FlyApp(
                        id=app.get("id", name),
                        name=name,
                        org_slug=org_slug,
                        network=app.get("network") or SHARED_NETWORK,
                    )
            except Exception as error:
                logger.error(
                    f"{self.service} - Error listing apps for organization {org_slug}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _fetch_ip_addresses(self):
        """Attach the allocated public IP addresses to each app.

        Public IP allocation is only exposed by the Fly.io GraphQL API, so it is
        read there instead of through the Machines API.
        """
        for org_slug in self.org_slugs:
            try:
                data = self._graphql(APPS_IP_QUERY, {"slug": org_slug})
                organization = data.get("organization") or {}
                for node in (organization.get("apps") or {}).get("nodes", []) or []:
                    app = self.apps.get(node.get("name", ""))
                    if not app:
                        continue

                    app.public_ips = [
                        FlyIPAddress(
                            id=ip.get("id", ""),
                            address=ip.get("address", ""),
                            type=ip.get("type", ""),
                            region=ip.get("region") or "global",
                        )
                        for ip in (node.get("ipAddresses") or {}).get("nodes", []) or []
                        if ip.get("address")
                    ]
            except Exception as error:
                logger.error(
                    f"{self.service} - Error fetching IP addresses for organization {org_slug}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def get_app(self, name: str) -> Optional[FlyApp]:
        """Return an in-scope app by name."""
        return self.apps.get(name)
