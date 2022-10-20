from boto3 import client, session
from moto import mock_acm

from providers.aws.lib.audit_info.models import AWS_Audit_Info
from providers.aws.services.acm.acm_service import ACM

AWS_ACCOUNT_NUMBER = 123456789012
AWS_REGION = "us-east-1"


class Test_ACM_Service:
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

    # Test ACM Service
    @mock_acm
    def test_service(self):
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert acm.service == "acm"

    # Test ACM Client
    @mock_acm
    def test_client(self):
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        for client in acm.regional_clients.values():
            assert client.__class__.__name__ == "ACM"

    # Test ACM Session
    @mock_acm
    def test__get_session__(self):
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert acm.session.__class__.__name__ == "Session"

    # Test ACM Session
    @mock_acm
    def test_audited_account(self):
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert acm.audited_account == AWS_ACCOUNT_NUMBER

    # Test ACM List Certificates
    @mock_acm
    def test__list_certificates__(self):
        # Generate ACM Client
        acm_client = client("acm", region_name=AWS_REGION)
        # Request ACM certificate
        certificate = acm_client.request_certificate(
            DomainName="test.com",
        )
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert len(acm.certificates) == 1
        assert acm.certificates[0].arn == certificate["CertificateArn"]

    # Test ACM Describe Certificates
    @mock_acm
    def test__describe_certificates__(self):
        # Generate ACM Client
        acm_client = client("acm", region_name=AWS_REGION)
        # Request ACM certificate
        certificate = acm_client.request_certificate(
            DomainName="test.com",
        )
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert acm.certificates[0].type == "AMAZON_ISSUED"
        assert acm.certificates[0].arn == certificate["CertificateArn"]
