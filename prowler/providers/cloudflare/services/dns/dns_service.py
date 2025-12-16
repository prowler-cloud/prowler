from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService
from prowler.providers.cloudflare.services.zones.zones_service import CloudflareZone


class CloudflareDNSRecord(BaseModel):
    """Represents a DNS record."""

    id: str
    name: str
    type: str
    content: str
    proxied: bool = False
    ttl: Optional[int] = None
    zone: CloudflareZone

    class Config:
        arbitrary_types_allowed = True


class DNS(CloudflareService):
    """Collect DNS records for each Cloudflare zone."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.records: list[CloudflareDNSRecord] = []
        self._list_dns_records()

    def _list_dns_records(self) -> None:
        """List DNS records for all zones."""
        logger.info("DNS - Listing DNS records...")
        # Import here to avoid circular imports
        from prowler.providers.cloudflare.services.zones.zones_client import (
            zones_client,
        )

        for zone in zones_client.zones.values():
            try:
                self._list_zone_records(zone)
            except Exception as error:
                logger.error(
                    f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        if self.records:
            record_types = {}
            for r in self.records:
                record_types[r.type] = record_types.get(r.type, 0) + 1
            types_summary = ", ".join(
                f"{t}: {c}" for t, c in sorted(record_types.items())
            )
            logger.info(
                f"DNS service collected {len(self.records)} record(s) across {len(zones_client.zones)} zone(s) - Types: {types_summary}"
            )
        else:
            logger.info(
                f"DNS service collected 0 records across {len(zones_client.zones)} zone(s)"
            )

    def _list_zone_records(self, zone: CloudflareZone) -> None:
        """List all DNS records for a zone."""
        seen_ids: set[str] = set()
        try:
            for record in self.client.dns.records.list(zone_id=zone.id):
                record_id = getattr(record, "id", "")
                if record_id in seen_ids:
                    break
                seen_ids.add(record_id)
                try:
                    self.records.append(
                        CloudflareDNSRecord(
                            id=record_id,
                            name=getattr(record, "name", ""),
                            type=getattr(record, "type", ""),
                            content=getattr(record, "content", ""),
                            proxied=getattr(record, "proxied", False),
                            ttl=getattr(record, "ttl", None),
                            zone=zone,
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
