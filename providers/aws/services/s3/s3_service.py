import threading
from dataclasses import dataclass

from lib.logger import logger
from providers.aws.aws_provider import current_audit_info, generate_regional_clients


################## S3
class S3:
    def __init__(self, audit_info):
        self.service = "s3"
        self.session = audit_info.audit_session
        self.client = self.session.client(self.service)
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.buckets = self.__list_buckets__()
        self.__threading_call__(self.__get_bucket_versioning__)
        self.__threading_call__(self.__get_bucket_logging__)
        self.__threading_call__(self.__get_bucket_acl__)

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

    def __list_buckets__(self):
        logger.info("S3 - Listing buckets...")
        try:
            buckets = []
            list_buckets = self.client.list_buckets()
            for bucket in list_buckets["Buckets"]:
                bucket_region = self.client.get_bucket_location(Bucket=bucket["Name"])[
                    "LocationConstraint"
                ]
                if not bucket_region:  # If us-east-1, bucket_region is none
                    bucket_region = "us-east-1"
                # Check if there are filter regions
                if current_audit_info.audited_regions:
                    if bucket_region in current_audit_info.audited_regions:
                        buckets.append(Bucket(bucket["Name"], bucket_region))
                else:
                    buckets.append(Bucket(bucket["Name"], bucket_region))
            return buckets
        except Exception as error:
            logger.error(
                f"{bucket_region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
        except Exception as error:
            logger.error(
                f"{bucket.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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

    def __get_bucket_acl__(self, bucket):
        logger.info("S3 - Get buckets acl...")
        try:
            grantees = []
            regional_client = self.regional_clients[bucket.region]
            acl_grants = regional_client.get_bucket_acl(Bucket=bucket.name)["Grants"]
            for grant in acl_grants:
                grantee = ACL_Grantee(grantee_type=grant["Grantee"])
                if "DisplayName" in grant["Grantee"]:
                    grantee.display_name = grant["Grantee"]["DisplayName"]
                if "EmailAddress" in grant["Grantee"]:
                    grantee.email_address = grant["Grantee"]["EmailAddress"]
                if "ID" in grant["Grantee"]:
                    grantee.ID = grant["Grantee"]["ID"]
                if "URI" in grant["Grantee"]:
                    grantee.URI = grant["Grantee"]["URI"]
                grantees.append(grantee)

            bucket.acl_grantee = grantees
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class Bucket:
    name: str
    versioning: bool
    logging: bool
    region: str
    acl_grantee: list
    logging_target_bucket: str

    def __init__(self, name, region):
        self.name = name
        self.versioning = False
        self.logging = False
        self.region = region
        self.acl_grantee = None
        self.logging_target_bucket = None


@dataclass
class ACL_Grantee:
    display_name: str
    email_address: str
    ID: str
    grantee_type: str
    URI: str

    def __init__(self, grantee_type):
        self.display_name = None
        self.email_address = None
        self.ID = None
        self.grantee_type = grantee_type
        self.URI = None
