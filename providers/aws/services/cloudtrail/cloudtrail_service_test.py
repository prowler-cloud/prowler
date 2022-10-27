from boto3 import session
from moto import mock_cloudtrail

from providers.aws.lib.audit_info.models import AWS_Audit_Info
from providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail

AWS_ACCOUNT_NUMBER = 123456789012


class Test_Cloudtrail_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
        )
        return audit_info

    # Test Cloudtrail Service
    @mock_cloudtrail
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert cloudtrail.service == "cloudtrail"

    # Test Cloudtrail client
    @mock_cloudtrail
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        for client in cloudtrail.regional_clients.values():
            assert client.__class__.__name__ == "CloudTrail"

    # Test Cloudtrail session
    @mock_cloudtrail
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert cloudtrail.session.__class__.__name__ == "Session"

    # Test Cloudtrail Session
    @mock_cloudtrail
    def test_audited_account(self):
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert cloudtrail.audited_account == AWS_ACCOUNT_NUMBER

    # WAITING FOR MOTO PR TO BE APPROVED (https://github.com/spulec/moto/pull/5607)

    # @mock_cloudtrail
    # @mock_s3
    # def test_describe_trails(self):
    #     cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
    #     s3_client_us_east_1 = client("s3", region_name="us-east-1")
    #     cloudtrail_client_eu_west_1 = client("cloudtrail", region_name="eu-west-1")
    #     s3_client_eu_west_1 = client("s3", region_name="eu-west-1")
    #     trail_name_us = "trail_test_us"
    #     bucket_name_us = "bucket_test_us"
    #     trail_name_eu = "trail_test_eu"
    #     bucket_name_eu = "bucket_test_eu"
    #     s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
    #     s3_client_eu_west_1.create_bucket(Bucket=bucket_name_eu, CreateBucketConfiguration={
    #     'LocationConstraint': 'eu-west-1'
    #     })
    #     cloudtrail_client_us_east_1.create_trail(
    #         Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
    #     )
    #     cloudtrail_client_eu_west_1.create_trail(
    #         Name=trail_name_eu, S3BucketName=bucket_name_eu, IsMultiRegionTrail=False
    #     )
    #     audit_info = self.set_mocked_audit_info()
    #     cloudtrail = Cloudtrail(audit_info)
    #     # Here we are expecting 2, but moto does something weird and return 46 records
    #     assert len(cloudtrail.trails) == 2
    #     assert cloudtrail.trails[0].name == "trail_name_us"
    #     assert cloudtrail.trails[1].name == "trail_name_eu"

    # @mock_cloudtrail
    # @mock_s3
    # def test_status_trails(self):
    #     cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
    #     s3_client_us_east_1 = client("s3", region_name="us-east-1")
    #     cloudtrail_client_eu_west_1 = client("cloudtrail", region_name="eu-west-1")
    #     s3_client_eu_west_1 = client("s3", region_name="eu-west-1")
    #     trail_name_us = "trail_test_us"
    #     bucket_name_us = "bucket_test_us"
    #     trail_name_eu = "trail_test_eu"
    #     bucket_name_eu = "bucket_test_eu"
    #     s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
    #     s3_client_eu_west_1.create_bucket(Bucket=bucket_name_eu, CreateBucketConfiguration={
    #     'LocationConstraint': 'eu-west-1'
    #     })
    #     cloudtrail_client_us_east_1.create_trail(
    #         Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
    #     )
    #     cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
    #     cloudtrail_client_eu_west_1.create_trail(
    #         Name=trail_name_eu, S3BucketName=bucket_name_eu, IsMultiRegionTrail=False
    #     )
    #     audit_info = self.set_mocked_audit_info()
    #     cloudtrail = Cloudtrail(audit_info)
    #     # Here we are expecting 2, but moto does something weird and return 46 records
    #     assert len(cloudtrail.trails) == 2
    #     assert cloudtrail.trails[0].name == "trail_name_us"
    #     assert cloudtrail.trails[1].name == "trail_name_eu"
    #     assert cloudtrail.trails[0].is_logging == False
    #     assert cloudtrail.trails[0].is_logging == True
