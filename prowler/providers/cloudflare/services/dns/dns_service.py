from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


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
            # Get zones directly from API to avoid circular dependency with zone_client
            zones = self._get_zones()

            for zone_id, zone_name in zones.items():
                seen_record_ids: set[str] = set()
                try:
                    for record in self.client.dns.records.list(zone_id=zone_id):
                        record_id = getattr(record, "id", None)
                        # Prevent infinite loop
                        if record_id in seen_record_ids:
                            break
                        seen_record_ids.add(record_id)

                        self.records.append(
                            CloudflareDNSRecord(
                                id=record_id,
                                zone_id=zone_id,
                                zone_name=zone_name,
                                name=getattr(record, "name", None),
                                type=getattr(record, "type", None),
                                content=getattr(record, "content", ""),
                                ttl=getattr(record, "ttl", None),
                                proxied=getattr(record, "proxied", False),
                            )
                        )
                except Exception as error:
                    logger.error(
                        f"{zone_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_zones(self) -> dict[str, str]:
        """Get zones directly from Cloudflare API.

        Returns:
            Dictionary mapping zone_id to zone_name.
        """
        zones = {}
        audited_accounts = self.provider.identity.audited_accounts
        filter_zones = self.provider.filter_zones
        seen_zone_ids: set[str] = set()

        try:
            for zone in self.client.zones.list():
                zone_id = getattr(zone, "id", None)
                # Prevent infinite loop - skip if we've seen this zone
                if zone_id in seen_zone_ids:
                    break
                seen_zone_ids.add(zone_id)

                zone_account = getattr(zone, "account", None)
                account_id = getattr(zone_account, "id", None) if zone_account else None

                # Filter by audited accounts
                if audited_accounts and account_id not in audited_accounts:
                    continue

                zone_name = getattr(zone, "name", None)

                # Apply zone filter if specified via --region
                if (
                    filter_zones
                    and zone_id not in filter_zones
                    and zone_name not in filter_zones
                ):
                    continue

                zones[zone_id] = zone_name
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return zones


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
