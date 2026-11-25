from datetime import datetime, timezone
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
        self._fetch_ssl_certificates()

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

    def _fetch_ssl_certificates(self):
        """Fetch SSL certificates for all domains via the certs list endpoint.

        ``GET /v8/certs/{domain}`` answers 404 for domains whose certificates
        are issued by Vercel, even though the certificates exist and cover the
        domains. ``GET /v4/certs`` lists those certificates, so match each
        domain against the ``cns`` of the listed certificates instead.
        """
        try:
            raw_certs = self._paginate("/v4/certs", "certs")
        except Exception as error:
            logger.error(
                "Domain - Error listing SSL certificates: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return

        certs = [self._build_ssl_certificate(cert) for cert in raw_certs or []]
        certs = [cert for cert in certs if cert is not None]

        for domain in self.domains.values():
            matches = [
                cert for cert in certs if self._cert_covers_domain(cert, domain.name)
            ]
            if matches:
                # Prefer the certificate valid for longest when several cover
                # the domain (e.g. an old certificate next to its renewal).
                domain.ssl_certificate = max(
                    matches,
                    key=lambda cert: cert.expires_at
                    or datetime.min.replace(tzinfo=timezone.utc),
                )
                logger.debug(f"Domain - Fetched SSL certificate for {domain.name}")

    @staticmethod
    def _build_ssl_certificate(data: dict) -> "Optional[VercelSSLCertificate]":
        """Build a VercelSSLCertificate from a certs API payload."""
        if not data:
            return None
        expires_at_ms = data.get("expiresAt")
        created_at_ms = data.get("createdAt")
        return VercelSSLCertificate(
            id=data.get("id", ""),
            created_at=(
                datetime.fromtimestamp(created_at_ms / 1000, tz=timezone.utc)
                if created_at_ms
                else None
            ),
            expires_at=(
                datetime.fromtimestamp(expires_at_ms / 1000, tz=timezone.utc)
                if expires_at_ms
                else None
            ),
            auto_renew=data.get("autoRenew", False),
            cns=data.get("cns", []),
        )

    @staticmethod
    def _cert_covers_domain(cert: "VercelSSLCertificate", domain_name: str) -> bool:
        """Check whether a certificate covers a domain.

        Matches an exact ``cns`` entry or a single-level wildcard entry
        (``*.example.com`` covers ``app.example.com`` but not
        ``deep.app.example.com``).
        """
        for cn in cert.cns:
            if cn == domain_name:
                return True
            if cn.startswith("*."):
                parent = cn[1:]
                if domain_name.endswith(parent) and domain_name.count(
                    "."
                ) == parent.count("."):
                    return True
        return False


class VercelSSLCertificate(BaseModel):
    """Vercel SSL certificate representation."""

    id: str = ""
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    auto_renew: bool = False
    cns: list[str] = Field(default_factory=list)


class VercelDomain(BaseModel):
    """Vercel domain representation."""

    name: str
    id: str = ""
    apex_name: Optional[str] = None
    verified: bool = False
    configured: bool = False
    ssl_certificate: Optional[VercelSSLCertificate] = None
    redirect: Optional[str] = None
    dns_records: list[dict] = Field(default_factory=list)
    team_id: Optional[str] = None
    project_id: Optional[str] = None
