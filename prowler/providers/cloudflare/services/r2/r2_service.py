from typing import Optional

from cloudflare import NotFoundError
from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService

# Buckets in a non-default jurisdiction are only visible/addressable when the
# jurisdiction is passed explicitly on every request.
R2_JURISDICTIONS = ("default", "eu", "fedramp")


class R2(CloudflareService):
    """Retrieve Cloudflare R2 buckets and their exposure-related configuration."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.buckets: list["CloudflareR2Bucket"] = []
        self._list_buckets()
        self.__threading_call__(self._get_bucket_details, self.buckets)

    def _list_buckets(self) -> None:
        logger.info("R2 - Listing R2 buckets...")
        for account_id in self.provider.identity.audited_accounts:
            seen: set[tuple[str, str]] = set()
            for jurisdiction in R2_JURISDICTIONS:
                try:
                    response = self.client.r2.buckets.list(
                        account_id=account_id, jurisdiction=jurisdiction
                    )
                    for bucket in getattr(response, "buckets", None) or []:
                        name = getattr(bucket, "name", None)
                        bucket_jurisdiction = (
                            getattr(bucket, "jurisdiction", None) or jurisdiction
                        )
                        if not name or (bucket_jurisdiction, name) in seen:
                            continue
                        seen.add((bucket_jurisdiction, name))
                        self.buckets.append(
                            CloudflareR2Bucket(
                                id=name,
                                name=name,
                                account_id=account_id,
                                jurisdiction=bucket_jurisdiction,
                                location=getattr(bucket, "location", None),
                                creation_date=getattr(bucket, "creation_date", None),
                            )
                        )
                except Exception as error:
                    log = logger.error if jurisdiction == "default" else logger.debug
                    log(
                        f"{account_id} R2 ({jurisdiction}) -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

    def _get_bucket_details(self, bucket: "CloudflareR2Bucket") -> None:
        kwargs = {
            "bucket_name": bucket.name,
            "account_id": bucket.account_id,
            "jurisdiction": bucket.jurisdiction,
        }
        try:
            managed = self.client.r2.buckets.domains.managed.list(**kwargs)
            bucket.public_dev_url_enabled = bool(getattr(managed, "enabled", False))
            bucket.public_dev_url = getattr(managed, "domain", None)
        except Exception as error:
            logger.error(
                f"{bucket.account_id}/{bucket.name} r2.dev -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        try:
            custom = self.client.r2.buckets.domains.custom.list(**kwargs)
            bucket.custom_domains = [
                CloudflareR2CustomDomain(
                    domain=domain.domain,
                    enabled=bool(getattr(domain, "enabled", False)),
                    min_tls=getattr(domain, "min_tls", None),
                )
                for domain in getattr(custom, "domains", None) or []
            ]
        except NotFoundError:
            bucket.custom_domains = []
        except Exception as error:
            logger.error(
                f"{bucket.account_id}/{bucket.name} custom domains -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        try:
            cors = self.client.r2.buckets.cors.get(**kwargs)
            bucket.cors_rules = [
                CloudflareR2CorsRule(
                    origins=list(getattr(rule.allowed, "origins", None) or []),
                    methods=list(getattr(rule.allowed, "methods", None) or []),
                )
                for rule in getattr(cors, "rules", None) or []
            ]
        except NotFoundError:
            # No CORS policy configured on the bucket
            bucket.cors_rules = []
        except Exception as error:
            logger.error(
                f"{bucket.account_id}/{bucket.name} CORS -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class CloudflareR2CustomDomain(BaseModel):
    domain: str
    enabled: bool = False
    min_tls: Optional[str] = None


class CloudflareR2CorsRule(BaseModel):
    origins: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)


class CloudflareR2Bucket(BaseModel):
    """Cloudflare R2 bucket representation."""

    id: str
    name: str
    account_id: str
    jurisdiction: str = "default"
    location: Optional[str] = None
    creation_date: Optional[str] = None
    public_dev_url_enabled: Optional[bool] = None
    public_dev_url: Optional[str] = None
    # None means the configuration could not be retrieved
    custom_domains: Optional[list[CloudflareR2CustomDomain]] = None
    cors_rules: Optional[list[CloudflareR2CorsRule]] = None
