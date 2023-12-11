import json
import threading
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## S3
class S3(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info)
        self.regions_with_buckets = []
        self.buckets = self.__list_buckets__(audit_info)
        self.__threading_call__(self.__get_bucket_versioning__)
        self.__threading_call__(self.__get_bucket_logging__)
        self.__threading_call__(self.__get_bucket_policy__)
        self.__threading_call__(self.__get_bucket_acl__)
        self.__threading_call__(self.__get_public_access_block__)
        self.__threading_call__(self.__get_bucket_encryption__)
        self.__threading_call__(self.__get_bucket_ownership_controls__)
        self.__threading_call__(self.__get_object_lock_configuration__)
        self.__threading_call__(self.__get_bucket_tagging__)

    # In the S3 service we override the "__threading_call__" method because we spawn a process per bucket instead of per region
    def __threading_call__(self, call):
        threads = []
        for bucket in self.buckets:
            threads.append(threading.Thread(target=call, args=(bucket,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_buckets__(self, audit_info):
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
                        if audit_info.audited_regions:
                            if bucket_region in audit_info.audited_regions:
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
                except Exception as error:
                    logger.error(
                        f"{bucket['Name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return buckets

    def __get_bucket_versioning__(self, bucket):
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
                    f"{bucket['Name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{bucket['Name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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

    def __get_bucket_encryption__(self, bucket):
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

    def __get_bucket_logging__(self, bucket):
        logger.info("S3 - Get buckets logging...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket_logging = regional_client.get_bucket_logging(Bucket=bucket.name)
            if "LoggingEnabled" in bucket_logging:
                bucket.logging = True
                bucket.logging_target_bucket = bucket_logging["LoggingEnabled"][
                    "TargetBucket"
                ]
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_public_access_block__(self, bucket):
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

    def __get_bucket_acl__(self, bucket):
        logger.info("S3 - Get buckets acl...")
        try:
            grantees = []
            regional_client = self.regional_clients[bucket.region]
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
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_bucket_policy__(self, bucket):
        logger.info("S3 - Get buckets policy...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket.policy = json.loads(
                regional_client.get_bucket_policy(Bucket=bucket.name)["Policy"]
            )
        except Exception as error:
            if "NoSuchBucketPolicy" in str(error):
                bucket.policy = {}
            else:
                if regional_client:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                else:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

    def __get_bucket_ownership_controls__(self, bucket):
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

    def __get_object_lock_configuration__(self, bucket):
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

    def __get_bucket_tagging__(self, bucket):
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


################## S3Control
class S3Control(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, audit_info, global_service=True)
        self.account_public_access_block = self.__get_public_access_block__()

    def __get_public_access_block__(self):
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
