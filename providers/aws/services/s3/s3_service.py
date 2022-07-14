import threading

from lib.logger import logger
from providers.aws.aws_provider import current_audit_info, generate_regional_clients


################## S3
class S3:
    def __init__(self, audit_info):
        self.service = "s3"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.__threading_call__(self.__list_buckets__)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients:
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_buckets__(self, regional_client):
        logger.info("S3 - Listing buckets...")
        try:
            list_buckets = regional_client.list_buckets()
            buckets = []
            for bucket in list_buckets["Buckets"]:
                bucket_region = regional_client.get_bucket_location(
                    Bucket=bucket["Name"]
                )["LocationConstraint"]
                if regional_client.region == bucket_region or (
                    regional_client.region == "us-east-1" and not bucket_region
                ):  # If us-east-1, bucket_region is none
                    buckets.append(bucket)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )
        else:
            regional_client.buckets = buckets


s3_client = S3(current_audit_info)
