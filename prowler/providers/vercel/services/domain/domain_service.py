from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.vercel.lib.service.service import VercelService


class Domain(VercelService):
    """Retrieve Vercel domains with DNS and SSL information."""

    def __init__(self, provider):
        super().__init__("Domain", provider)
        self.domains: dict[str, VercelDomain] = {}
        self._list_domains()
        self.__threading_call__(self._fetch_dns_records, list(self.domains.values()))

    def _list_domains(self):
        """List all domains."""
        try:
            raw_domains = self._paginate("/v5/domains", "domains")

            seen_names: set[str] = set()

            for domain in raw_domains:
                domain_name = domain.get("name", "")
                if not domain_name or domain_name in seen_names:
                    continue
                seen_names.add(domain_name)

                ssl_cert = None
                cert_data = domain.get("certs", [])
                if cert_data:
                    ssl_cert = (
                        cert_data[0] if isinstance(cert_data, list) else cert_data
                    )

                self.domains[domain_name] = VercelDomain(
                    name=domain_name,
                    id=domain.get("id", domain_name),
                    apex_name=domain.get("apexName"),
                    verified=domain.get("verified", False),
                    configured=(
                        domain.get("configured", False)
                        if "configured" in domain
                        else domain.get("verified", False)
                    ),
                    ssl_certificate=ssl_cert,
                    redirect=domain.get("redirect"),
                    team_id=self.provider.session.team_id,
                )

            logger.info(f"Domain - Found {len(self.domains)} domain(s)")

        except Exception as error:
            logger.error(
                f"Domain - Error listing domains: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _fetch_dns_records(self, domain: "VercelDomain"):
        """Fetch DNS records for a single domain."""
        try:
            data = self._get(f"/v4/domains/{domain.name}/records")
            if data and "records" in data:
                domain.dns_records = data["records"]
                logger.debug(
                    f"Domain - Fetched {len(domain.dns_records)} DNS records for {domain.name}"
                )
        except Exception as error:
            logger.error(
                f"Domain - Error fetching DNS records for {domain.name}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class VercelDomain(BaseModel):
    """Vercel domain representation."""

    name: str
    id: str = ""
    apex_name: Optional[str] = None
    verified: bool = False
    configured: bool = False
    ssl_certificate: Optional[dict] = None
    redirect: Optional[str] = None
    dns_records: list[dict] = Field(default_factory=list)
    team_id: Optional[str] = None
    project_id: Optional[str] = None
