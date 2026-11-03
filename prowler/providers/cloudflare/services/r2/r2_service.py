from typing import ClassVar, Optional

from cloudflare import NotFoundError, PermissionDeniedError
from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService

# Buckets in a non-default jurisdiction are only visible/addressable when the
# jurisdiction is passed explicitly on every request.
R2_JURISDICTIONS = ("default", "eu", "fedramp")
# Maximum page size accepted by the List Buckets API.
R2_BUCKETS_PAGE_SIZE = 1000
# Only FedRAMP accounts can list FedRAMP buckets; other accounts get a 403,
# which is expected. Any other error is a real listing failure.
OPTIONAL_JURISDICTIONS = {"fedramp"}


class R2(CloudflareService):
    """Retrieve Cloudflare R2 buckets and their exposure-related configuration.

    Data that could not be retrieved is tracked per account (``*_failed_accounts``)
    so checks can report it as MANUAL instead of silently omitting it.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.buckets: list["CloudflareR2Bucket"] = []
        self.list_failed_accounts: set[str] = set()
        self.dev_url_failed_accounts: set[str] = set()
        self.custom_domains_failed_accounts: set[str] = set()
        self.cors_failed_accounts: set[str] = set()
        self._list_buckets()
        self.__threading_call__(self._get_bucket_details, self.buckets)

    def _list_buckets(self) -> None:
        logger.info("R2 - Listing R2 buckets...")
        for account_id in self.provider.identity.audited_accounts:
            seen: set[tuple[str, str]] = set()
            for jurisdiction in R2_JURISDICTIONS:
                try:
                    # Read the whole jurisdiction first so a failure on a later
                    # page does not leave a partial bucket list behind.
                    jurisdiction_buckets = list(
                        self._list_jurisdiction_buckets(account_id, jurisdiction)
                    )
                except Exception as error:
                    if jurisdiction in OPTIONAL_JURISDICTIONS and isinstance(
                        error, PermissionDeniedError
                    ):
                        logger.debug(
                            f"{account_id} R2 ({jurisdiction}) -- {error.__class__.__name__}: {error}"
                        )
                        continue
                    self.list_failed_accounts.add(account_id)
                    logger.error(
                        f"{account_id} R2 ({jurisdiction}) -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    continue
                for bucket in jurisdiction_buckets:
                    name = getattr(bucket, "name", None)
                    bucket_jurisdiction = (
                        getattr(bucket, "jurisdiction", None) or jurisdiction
                    )
                    if not name or (bucket_jurisdiction, name) in seen:
                        continue
                    seen.add((bucket_jurisdiction, name))
                    self.buckets.append(
                        CloudflareR2Bucket(
                            # Names are only unique per account and jurisdiction.
                            id=f"{account_id}/{bucket_jurisdiction}/{name}",
                            name=name,
                            account_id=account_id,
                            jurisdiction=bucket_jurisdiction,
                            location=getattr(bucket, "location", None),
                            creation_date=getattr(bucket, "creation_date", None),
                        )
                    )

    def _list_jurisdiction_buckets(self, account_id: str, jurisdiction: str):
        """Yield every bucket of a jurisdiction, following pagination.

        The SDK returns a single page and drops the pagination cursor, so pages
        are walked with ``start_after`` (buckets are ordered by name).
        """
        start_after = None
        while True:
            kwargs = {
                "account_id": account_id,
                "jurisdiction": jurisdiction,
                "per_page": R2_BUCKETS_PAGE_SIZE,
            }
            if start_after:
                kwargs["start_after"] = start_after
            buckets = getattr(self.client.r2.buckets.list(**kwargs), "buckets", None)
            buckets = buckets or []
            yield from buckets
            last_name = getattr(buckets[-1], "name", None) if buckets else None
            # Stop on a short page, or if the API does not advance (loop guard).
            if (
                len(buckets) < R2_BUCKETS_PAGE_SIZE
                or not last_name
                or last_name == start_after
            ):
                return
            start_after = last_name

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
            self.dev_url_failed_accounts.add(bucket.account_id)
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
            self.custom_domains_failed_accounts.add(bucket.account_id)
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
            self.cors_failed_accounts.add(bucket.account_id)
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
    is_global_resource: ClassVar[bool] = True

    @property
    def unique_name(self) -> str:
        """Bucket name, prefixed with its jurisdiction when not the default one.

        Bucket names are only unique within a jurisdiction, and the finding UID
        is derived from the resource name.
        """
        if self.jurisdiction and self.jurisdiction != "default":
            return f"{self.jurisdiction}/{self.name}"
        return self.name
