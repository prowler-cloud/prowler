from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService
from prowler.providers.cloudflare.services.zone.zone_client import zone_client


class DNS(CloudflareService):
    """Retrieve Cloudflare DNS records for all zones."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.records: list["CloudflareDNSRecord"] = []
        self._list_dns_records()

    def _list_dns_records(self) -> None:
        """List DNS records for all zones."""
        logger.info("DNS - Listing DNS records...")
        try:
            for zone in zone_client.zones.values():
                seen_record_ids: set[str] = set()
                try:
                    for record in self.client.dns.records.list(zone_id=zone.id):
                        record_id = getattr(record, "id", None)
                        # Prevent infinite loop
                        if record_id in seen_record_ids:
                            break
                        seen_record_ids.add(record_id)

                        self.records.append(
                            CloudflareDNSRecord(
                                id=record_id,
                                zone_id=zone.id,
                                zone_name=zone.name,
                                name=getattr(record, "name", None),
                                type=getattr(record, "type", None),
                                content=getattr(record, "content", ""),
                                ttl=getattr(record, "ttl", None),
                                proxied=getattr(record, "proxied", False),
                            )
                        )
                except Exception as error:
                    logger.error(
                        f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class CloudflareDNSRecord(BaseModel):
    """Cloudflare DNS record representation."""

    id: str
    zone_id: str
    zone_name: str
    name: Optional[str] = None
    type: Optional[str] = None
    content: str = ""
    ttl: Optional[int] = None
    proxied: bool = False
