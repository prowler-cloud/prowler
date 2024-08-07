import json
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class S3(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.account_arn_template = f"arn:{self.audited_partition}:s3:{self.region}:{self.audited_account}:account"
        self.regions_with_buckets = []
        self.buckets = self._list_buckets(provider)
        self.__threading_call__(self._get_bucket_versioning, self.buckets)
        self.__threading_call__(self._get_bucket_logging, self.buckets)
        self.__threading_call__(self._get_bucket_policy, self.buckets)
        self.__threading_call__(self._get_bucket_acl, self.buckets)
        self.__threading_call__(self._get_public_access_block, self.buckets)
        self.__threading_call__(self._get_bucket_encryption, self.buckets)
        self.__threading_call__(self._get_bucket_ownership_controls, self.buckets)
        self.__threading_call__(self._get_object_lock_configuration, self.buckets)
        self.__threading_call__(self._get_bucket_tagging, self.buckets)

    def _list_buckets(self, provider):
        logger.info("S3 - Listing buckets...")
        buckets = []
        try:
            list_buckets = self.client.list_buckets()
            for bucket in list_buckets["Buckets"]:
                try:
                    bucket_region = self.client.get_bucket_location(
                        Bucket=bucket["Name"]
                    )["LocationConstraint"]
                    if bucket_region == "EU":  # If EU, bucket_region is eu-west-1
                        bucket_region = "eu-west-1"
                    if not bucket_region:  # If None, bucket_region is us-east-1
                        bucket_region = "us-east-1"
                    # Arn
                    arn = f"arn:{self.audited_partition}:s3:::{bucket['Name']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.regions_with_buckets.append(bucket_region)
                        # Check if there are filter regions
                        if provider.identity.audited_regions:
                            # FIXME: what if the bucket comes from a CloudTrail bucket in another audited region
                            if bucket_region in provider.identity.audited_regions:
                                buckets.append(
                                    Bucket(
                                        name=bucket["Name"],
                                        arn=arn,
                                        region=bucket_region,
                                    )
                                )
                        else:
                            buckets.append(
                                Bucket(
                                    name=bucket["Name"], arn=arn, region=bucket_region
                                )
                            )
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchBucket":
                        logger.warning(
                            f"{bucket['Name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{bucket['Name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                except Exception as error:
                    logger.error(
                        f"{bucket['Name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except ClientError as error:
            if error.response["Error"]["Code"] == "NotSignedUp":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return buckets

    def _get_bucket_versioning(self, bucket):
        logger.info("S3 - Get buckets versioning...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket_versioning = regional_client.get_bucket_versioning(
                Bucket=bucket.name
            )
            if "Status" in bucket_versioning:
                if "Enabled" == bucket_versioning["Status"]:
                    bucket.versioning = True
            if "MFADelete" in bucket_versioning:
                if "Enabled" == bucket_versioning["MFADelete"]:
                    bucket.mfa_delete = True
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if bucket.region:
                logger.error(
                    f"{bucket.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_bucket_encryption(self, bucket):
        logger.info("S3 - Get buckets encryption...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket.encryption = regional_client.get_bucket_encryption(
                Bucket=bucket.name
            )["ServerSideEncryptionConfiguration"]["Rules"][0][
                "ApplyServerSideEncryptionByDefault"
            ][
                "SSEAlgorithm"
            ]
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(error):
                bucket.encryption = None
            elif regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_bucket_logging(self, bucket):
        logger.info("S3 - Get buckets logging...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket_logging = regional_client.get_bucket_logging(Bucket=bucket.name)
            if "LoggingEnabled" in bucket_logging:
                bucket.logging = True
                bucket.logging_target_bucket = bucket_logging["LoggingEnabled"][
                    "TargetBucket"
                ]
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_public_access_block(self, bucket):
        logger.info("S3 - Get buckets public access block...")
        try:
            regional_client = self.regional_clients[bucket.region]
            public_access_block = regional_client.get_public_access_block(
                Bucket=bucket.name
            )["PublicAccessBlockConfiguration"]
            bucket.public_access_block = PublicAccessBlock(
                block_public_acls=public_access_block["BlockPublicAcls"],
                ignore_public_acls=public_access_block["IgnorePublicAcls"],
                block_public_policy=public_access_block["BlockPublicPolicy"],
                restrict_public_buckets=public_access_block["RestrictPublicBuckets"],
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            elif (
                error.response["Error"]["Code"]
                == "NoSuchPublicAccessBlockConfiguration"
            ):
                # Set all block as False
                bucket.public_access_block = PublicAccessBlock(
                    block_public_acls=False,
                    ignore_public_acls=False,
                    block_public_policy=False,
                    restrict_public_buckets=False,
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_bucket_acl(self, bucket):
        logger.info("S3 - Get buckets acl...")
        try:
            regional_client = self.regional_clients[bucket.region]
            grantees = []
            acl_grants = regional_client.get_bucket_acl(Bucket=bucket.name)["Grants"]
            for grant in acl_grants:
                grantee = ACL_Grantee(type=grant["Grantee"]["Type"])
                if "DisplayName" in grant["Grantee"]:
                    grantee.display_name = grant["Grantee"]["DisplayName"]
                if "ID" in grant["Grantee"]:
                    grantee.ID = grant["Grantee"]["ID"]
                if "URI" in grant["Grantee"]:
                    grantee.URI = grant["Grantee"]["URI"]
                if "Permission" in grant:
                    grantee.permission = grant["Permission"]
                grantees.append(grantee)
            bucket.acl_grantees = grantees
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_bucket_policy(self, bucket):
        logger.info("S3 - Get buckets policy...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket.policy = json.loads(
                regional_client.get_bucket_policy(Bucket=bucket.name)["Policy"]
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucketPolicy":
                bucket.policy = {}
            elif error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_bucket_ownership_controls(self, bucket):
        logger.info("S3 - Get buckets ownership controls...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket.ownership = regional_client.get_bucket_ownership_controls(
                Bucket=bucket.name
            )["OwnershipControls"]["Rules"][0]["ObjectOwnership"]
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            elif error.response["Error"]["Code"] == "OwnershipControlsNotFoundError":
                bucket.ownership = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_object_lock_configuration(self, bucket):
        logger.info("S3 - Get buckets ownership controls...")
        try:
            regional_client = self.regional_clients[bucket.region]
            regional_client.get_object_lock_configuration(Bucket=bucket.name)
            bucket.object_lock = True
        except Exception as error:
            if (
                "ObjectLockConfigurationNotFoundError" in str(error)
                or error.response["Error"]["Code"] == "NoSuchBucket"
            ):
                bucket.object_lock = False
                if regional_client:
                    logger.warning(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                else:
                    logger.warning(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            else:
                if regional_client:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                else:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

    def _get_bucket_tagging(self, bucket):
        logger.info("S3 - Get buckets logging...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket_tags = regional_client.get_bucket_tagging(Bucket=bucket.name)[
                "TagSet"
            ]
            bucket.tags = bucket_tags
        except ClientError as error:
            bucket.tags = []
            if error.response["Error"]["Code"] != "NoSuchTagSet":
                if error.response["Error"]["Code"] == "NoSuchBucket":
                    logger.warning(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                else:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class S3Control(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.account_public_access_block = self._get_public_access_block()
        self.access_points = {}
        self.__threading_call__(self._list_access_points)
        self.__threading_call__(self._get_access_point, self.access_points.values())

    def _get_public_access_block(self):
        logger.info("S3 - Get account public access block...")
        try:
            public_access_block = self.client.get_public_access_block(
                AccountId=self.audited_account
            )["PublicAccessBlockConfiguration"]
            return PublicAccessBlock(
                block_public_acls=public_access_block["BlockPublicAcls"],
                ignore_public_acls=public_access_block["IgnorePublicAcls"],
                block_public_policy=public_access_block["BlockPublicPolicy"],
                restrict_public_buckets=public_access_block["RestrictPublicBuckets"],
            )
        except Exception as error:
            if "NoSuchPublicAccessBlockConfiguration" in str(error):
                # Set all block as False
                return PublicAccessBlock(
                    block_public_acls=False,
                    ignore_public_acls=False,
                    block_public_policy=False,
                    restrict_public_buckets=False,
                )
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_access_points(self, regional_client):
        logger.info("S3 - Listing account access points...")
        try:
            list_access_points = regional_client.list_access_points(
                AccountId=self.audited_account
            )["AccessPointList"]
            for ap in list_access_points:
                self.access_points[ap["AccessPointArn"]] = AccessPoint(
                    account_id=self.audited_account,
                    name=ap["Name"],
                    bucket=ap["Bucket"],
                    region=regional_client.region,
                )
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchMultiRegionAccessPoint":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_access_point(self, ap):
        logger.info("S3 - Get account access point...")
        try:
            access_point = self.regional_clients[ap.region].get_access_point(
                AccountId=ap.account_id, Name=ap.name
            )
            ap.public_access_block = PublicAccessBlock(
                block_public_acls=access_point.get(
                    "PublicAccessBlockConfiguration", {}
                ).get("BlockPublicAcls", False),
                ignore_public_acls=access_point.get(
                    "PublicAccessBlockConfiguration", {}
                ).get("IgnorePublicAcls", False),
                block_public_policy=access_point.get(
                    "PublicAccessBlockConfiguration", {}
                ).get("BlockPublicPolicy", False),
                restrict_public_buckets=access_point.get(
                    "PublicAccessBlockConfiguration", {}
                ).get("RestrictPublicBuckets", False),
            )
        except Exception as error:
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class ACL_Grantee(BaseModel):
    display_name: Optional[str]
    ID: Optional[str]
    type: str
    URI: Optional[str]
    permission: Optional[str]


class PublicAccessBlock(BaseModel):
    block_public_acls: bool
    ignore_public_acls: bool
    block_public_policy: bool
    restrict_public_buckets: bool


class AccessPoint(BaseModel):
    account_id: str
    name: str
    bucket: str
    public_access_block: Optional[PublicAccessBlock]
    region: str


class Bucket(BaseModel):
    name: str
    arn: str
    versioning: bool = False
    logging: bool = False
    public_access_block: Optional[PublicAccessBlock]
    acl_grantees: list[ACL_Grantee] = []
    policy: dict = {}
    encryption: Optional[str]
    region: str
    logging_target_bucket: Optional[str]
    ownership: Optional[str]
    object_lock: bool = False
    mfa_delete: bool = False
    tags: Optional[list] = []
