import json
import threading
from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## S3
class S3:
    def __init__(self, audit_info):
        self.service = "s3"
        self.session = audit_info.audit_session
        self.client = self.session.client(self.service)
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.buckets = self.__list_buckets__(audit_info)
        self.__threading_call__(self.__get_bucket_versioning__)
        self.__threading_call__(self.__get_bucket_logging__)
        self.__threading_call__(self.__get_bucket_policy__)
        self.__threading_call__(self.__get_bucket_acl__)
        self.__threading_call__(self.__get_public_access_block__)
        self.__threading_call__(self.__get_bucket_encryption__)
        self.__threading_call__(self.__get_bucket_ownership_controls__)

    def __get_session__(self):
        return self.session

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
        try:
            buckets = []
            list_buckets = self.client.list_buckets()
            for bucket in list_buckets["Buckets"]:
                try:
                    bucket_region = self.client.get_bucket_location(
                        Bucket=bucket["Name"]
                    )["LocationConstraint"]
                    if not bucket_region:  # If us-east-1, bucket_region is none
                        bucket_region = "us-east-1"
                    # Check if there are filter regions
                    if audit_info.audited_regions:
                        if bucket_region in audit_info.audited_regions:
                            buckets.append(Bucket(bucket["Name"], bucket_region))
                    else:
                        buckets.append(Bucket(bucket["Name"], bucket_region))
                except Exception as error:
                    logger.error(
                        f"{bucket_region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            return buckets
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

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
        except Exception as error:
            logger.error(
                f"{bucket.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
        except Exception as error:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(error):
                bucket.encryption = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_public_access_block__(self, bucket):
        logger.info("S3 - Get buckets public access block...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket.public_access_block = PublicAccessBlock(
                regional_client.get_public_access_block(Bucket=bucket.name)[
                    "PublicAccessBlockConfiguration"
                ]
            )
        except Exception as error:
            if "NoSuchPublicAccessBlockConfiguration" in str(error):
                # Set all block as False
                bucket.public_access_block = PublicAccessBlock(
                    {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    }
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_bucket_ownership_controls__(self, bucket):
        logger.info("S3 - Get buckets ownership controls...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket.ownership = regional_client.get_bucket_ownership_controls(
                Bucket=bucket.name
            )["OwnershipControls"]["Rules"][0]["ObjectOwnership"]
        except Exception as error:
            if "OwnershipControlsNotFoundError" in str(error):
                bucket.ownership = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


################## S3Control
class S3Control:
    def __init__(self, audit_info):
        self.service = "s3control"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        global_client = generate_regional_clients(
            self.service, audit_info, global_service=True
        )
        if global_client:
            self.client = list(global_client.values())[0]
            self.region = self.client.region
            self.account_public_access_block = self.__get_public_access_block__()

    def __get_session__(self):
        return self.session

    def __get_public_access_block__(self):
        logger.info("S3 - Get account public access block...")
        try:
            return PublicAccessBlock(
                self.client.get_public_access_block(AccountId=self.audited_account)[
                    "PublicAccessBlockConfiguration"
                ]
            )
        except Exception as error:
            if "NoSuchPublicAccessBlockConfiguration" in str(error):
                # Set all block as False
                return PublicAccessBlock(
                    {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    }
                )
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class ACL_Grantee:
    display_name: str
    ID: str
    type: str
    URI: str
    permission: str

    def __init__(self, type):
        self.display_name = None
        self.ID = None
        self.type = type
        self.URI = None
        self.permission = None


@dataclass
class PublicAccessBlock:
    block_public_acls: bool
    ignore_public_acls: bool
    block_public_policy: bool
    restrict_public_buckets: bool

    def __init__(self, configuration):
        self.block_public_acls = configuration["BlockPublicAcls"]
        self.ignore_public_acls = configuration["IgnorePublicAcls"]
        self.block_public_policy = configuration["BlockPublicPolicy"]
        self.restrict_public_buckets = configuration["RestrictPublicBuckets"]


@dataclass
class Bucket:
    name: str
    versioning: bool
    logging: bool
    public_access_block: PublicAccessBlock
    acl_grantees: list[ACL_Grantee]
    policy: dict
    encryption: str
    region: str
    logging_target_bucket: str
    ownership: str
    mfa_delete: bool

    def __init__(self, name, region):
        self.name = name
        self.versioning = False
        self.logging = False
        # Set all block as False
        self.public_access_block = PublicAccessBlock(
            {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        )
        self.acl_grantees = []
        self.policy = {}
        self.encryption = None
        self.region = region
        self.logging_target_bucket = None
        self.ownership = None
        self.mfa_delete = False
