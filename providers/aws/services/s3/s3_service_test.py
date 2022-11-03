from boto3 import client, session
from moto import mock_s3

from providers.aws.lib.audit_info.models import AWS_Audit_Info
from providers.aws.services.s3.s3_service import S3

AWS_ACCOUNT_NUMBER = 123456789012


class Test_S3_Service:
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

    # Test S3 Service
    @mock_s3
    def test_service(self):
        # S3 client for this test class
        audit_info = self.set_mocked_audit_info()
        s3 = S3(audit_info)
        assert s3.service == "s3"

    # Test S3 Client
    @mock_s3
    def test_client(self):
        # S3 client for this test class
        audit_info = self.set_mocked_audit_info()
        s3 = S3(audit_info)
        assert s3.client.__class__.__name__ == "S3"

    # Test S3 Session
    @mock_s3
    def test__get_session__(self):
        # S3 client for this test class
        audit_info = self.set_mocked_audit_info()
        s3 = S3(audit_info)
        assert s3.session.__class__.__name__ == "Session"

    # Test S3 Regional Clients
    # @mock_s3
    # def test_regional_clients(self):
    #     # S3 client for this test class
    #     audit_info = self.set_mocked_audit_info()
    #     s3 = S3(audit_info)
    #     print(s3.regional_clients.keys())

    # Test S3 Session
    @mock_s3
    def test_audited_account(self):
        # S3 client for this test class
        audit_info = self.set_mocked_audit_info()
        s3 = S3(audit_info)
        assert s3.audited_account == AWS_ACCOUNT_NUMBER

    # Test S3 List Buckets
    @mock_s3
    def test__list_buckets__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(Bucket=bucket_name)

        # S3 client for this test class
        audit_info = self.set_mocked_audit_info()
        s3 = S3(audit_info)

        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name

    # Test S3 Get Bucket Versioning
    @mock_s3
    def test__get_bucket_versioning__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(Bucket=bucket_name)
        # Set Bucket Versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"MFADelete": "Disabled", "Status": "Enabled"},
        )
        # S3 client for this test class
        audit_info = self.set_mocked_audit_info()
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert s3.buckets[0].versioning == True

    # Test S3 Get Bucket Versioning
    @mock_s3
    def test__get_bucket_acl__(self):
        s3_client = client("s3")
        bucket_name = "test-bucket"
        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.put_bucket_acl(
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "DisplayName": "test",
                            "ID": "test_ID",
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "Permission": "READ",
                    },
                ],
                "Owner": {"DisplayName": "test", "ID": "test_id"},
            },
            Bucket=bucket_name,
        )
        audit_info = self.set_mocked_audit_info()
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert s3.buckets[0].acl_grantee[0].display_name == "test"
        assert s3.buckets[0].acl_grantee[0].ID == "test_ID"
        assert s3.buckets[0].acl_grantee[0].type == "Group"
        assert (
            s3.buckets[0].acl_grantee[0].URI
            == "http://acs.amazonaws.com/groups/global/AllUsers"
        )

    # Test S3 Get Bucket Versioning
    # @mock_s3
    # def test__get_bucket_logging__(self):
    #     # Generate S3 Client
    #     s3_client = client("s3")
    #     # Create S3 Bucket
    #     bucket_name = "test-bucket"
    #     s3_client.create_bucket(
    #         Bucket=bucket_name,
    #         ACL='private'
    #     )
    #     # Set Bucket Logging
    #     s3_client.put_bucket_logging(
    #         Bucket=bucket_name,
    #         BucketLoggingStatus={
    #             'LoggingEnabled': {
    #                 'TargetBucket': bucket_name,
    #                 'TargetGrants': [
    #                         {
    #                             'Grantee': {
    #                                 'Type': 'Group',
    #                                 'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
    #                             },
    #                             'Permission': 'READ_ACP'
    #                         },
    #                         {
    #                             'Grantee': {
    #                                 'Type': 'Group',
    #                                 'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
    #                             },
    #                             'Permission': 'WRITE'
    #                         }
    #                     ],
    #                 'TargetPrefix': 'test-prefix'
    #             }
    #         }
    #     )
    #     # S3 client for this test class
    #     audit_info = self.set_mocked_audit_info()
    #     s3 = S3(audit_info)
    #     print(s3.buckets)
    # assert len(s3.buckets) == 1
    # assert s3.buckets[0].name == bucket_name
    # assert s3.buckets[0].versioning == True
