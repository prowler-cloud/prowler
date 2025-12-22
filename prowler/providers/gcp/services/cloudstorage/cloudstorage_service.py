from typing import Optional

from googleapiclient.errors import HttpError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.gcp.config import DEFAULT_RETRY_ATTEMPTS
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.gcp.lib.service.service import GCPService


class CloudStorage(GCPService):
    def __init__(self, provider: GcpProvider):
        super().__init__("storage", provider)
        self.buckets = []
        self.vpc_service_controls_protected_projects = set()
        self._get_buckets()

    def _get_buckets(self):
        for project_id in self.project_ids:
            try:
                request = self.client.buckets().list(project=project_id)
                while request is not None:
                    response = request.execute(num_retries=DEFAULT_RETRY_ATTEMPTS)
                    for bucket in response.get("items", []):
                        bucket_iam = (
                            self.client.buckets()
                            .getIamPolicy(bucket=bucket["id"])
                            .execute(num_retries=DEFAULT_RETRY_ATTEMPTS)["bindings"]
                        )
                        public = False
                        if "allAuthenticatedUsers" in str(
                            bucket_iam
                        ) or "allUsers" in str(bucket_iam):
                            public = True

                        lifecycle_rules = None
                        lifecycle = bucket.get("lifecycle")
                        if isinstance(lifecycle, dict):
                            rules = lifecycle.get("rule")
                            if isinstance(rules, list):
                                lifecycle_rules = rules

                        versioning_enabled = bucket.get("versioning", {}).get(
                            "enabled", False
                        )

                        soft_delete_enabled = False
                        soft_delete_policy = bucket.get("softDeletePolicy")
                        if isinstance(soft_delete_policy, dict):
                            retention = soft_delete_policy.get(
                                "retentionDurationSeconds"
                            )
                            if retention and int(retention) > 0:
                                soft_delete_enabled = True

                        logging_info = bucket.get("logging", {})
                        logging_bucket = logging_info.get("logBucket")
                        logging_prefix = logging_info.get("logObjectPrefix")

                        retention_policy_raw = bucket.get("retentionPolicy")
                        retention_policy = None
                        if isinstance(retention_policy_raw, dict):
                            rp_seconds = retention_policy_raw.get("retentionPeriod")
                            if rp_seconds:
                                retention_policy = RetentionPolicy(
                                    retention_period=int(rp_seconds),
                                    is_locked=bool(
                                        retention_policy_raw.get("isLocked", False)
                                    ),
                                    effective_time=retention_policy_raw.get(
                                        "effectiveTime"
                                    ),
                                )

                        self.buckets.append(
                            Bucket(
                                name=bucket["name"],
                                id=bucket["id"],
                                region=bucket["location"].lower(),
                                uniform_bucket_level_access=bucket["iamConfiguration"][
                                    "uniformBucketLevelAccess"
                                ]["enabled"],
                                public=public,
                                retention_policy=retention_policy,
                                project_id=project_id,
                                lifecycle_rules=lifecycle_rules,
                                versioning_enabled=versioning_enabled,
                                soft_delete_enabled=soft_delete_enabled,
                                logging_bucket=logging_bucket,
                                logging_prefix=logging_prefix,
                            )
                        )

                    request = self.client.buckets().list_next(
                        previous_request=request, previous_response=response
                    )
            except HttpError as http_error:
                # Check if the error is due to VPC Service Controls blocking the API
                if "vpcServiceControlsUniqueIdentifier" in str(http_error):
                    self.vpc_service_controls_protected_projects.add(project_id)
                    logger.warning(
                        f"Project {project_id} is protected by VPC Service Controls for Cloud Storage API."
                    )
                else:
                    logger.error(
                        f"{http_error.__class__.__name__}[{http_error.__traceback__.tb_lineno}]: {http_error}"
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class RetentionPolicy(BaseModel):
    retention_period: int
    is_locked: bool
    effective_time: Optional[str] = None


class Bucket(BaseModel):
    name: str
    id: str
    region: str
    uniform_bucket_level_access: bool
    public: bool
    project_id: str
    retention_policy: Optional[RetentionPolicy] = None
    lifecycle_rules: Optional[list[dict]] = None
    versioning_enabled: Optional[bool] = False
    soft_delete_enabled: Optional[bool] = False
    logging_bucket: Optional[str] = None
    logging_prefix: Optional[str] = None
