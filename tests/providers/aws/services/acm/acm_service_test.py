import uuid
from datetime import datetime

import botocore
from boto3 import session
from freezegun import freeze_time
from mock import patch

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.acm.acm_service import ACM

# from moto import mock_acm


AWS_ACCOUNT_NUMBER = 123456789012
AWS_REGION = "us-east-1"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call

certificate_arn = (
    f"arn:aws:acm:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:certificate/{str(uuid.uuid4())}"
)
certificate_name = "test-certificate.com"
certificate_type = "AMAZON_ISSUED"


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "ListCertificates":
        return {
            "CertificateSummaryList": [
                {
                    "CertificateArn": certificate_arn,
                    "DomainName": certificate_name,
                    "SubjectAlternativeNameSummaries": [
                        "test-certificate-2.com",
                    ],
                    "HasAdditionalSubjectAlternativeNames": False,
                    "Status": "ISSUED",
                    "Type": certificate_type,
                    "KeyAlgorithm": "RSA_4096",
                    "KeyUsages": ["DIGITAL_SIGNATURE"],
                    "ExtendedKeyUsages": ["TLS_WEB_SERVER_AUTHENTICATION"],
                    "InUse": True,
                    "Exported": False,
                    "RenewalEligibility": "ELIGIBLE",
                    "NotBefore": datetime(2024, 1, 1),
                    "NotAfter": datetime(2024, 1, 1),
                    "CreatedAt": datetime(2024, 1, 1),
                    "IssuedAt": datetime(2024, 1, 1),
                    "ImportedAt": datetime(2024, 1, 1),
                    "RevokedAt": datetime(2024, 1, 1),
                }
            ]
        }
    if operation_name == "DescribeCertificate":
        if kwargs["CertificateArn"] == certificate_arn:
            return {
                "Certificate": {
                    "Options": {"CertificateTransparencyLoggingPreference": "DISABLED"},
                }
            }
    if operation_name == "ListTagsForCertificate":
        if kwargs["CertificateArn"] == certificate_arn:
            return {
                "Tags": [
                    {"Key": "test", "Value": "test"},
                ]
            }

    return make_api_call(self, operation_name, kwargs)


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch(
    "prowler.providers.aws.services.acm.acm_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
# Freeze time
@freeze_time("2023-01-01")
# FIXME: Pending Moto PR to update ACM responses
class Test_ACM_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
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
            audit_resources=None,
        )
        return audit_info

    # Test ACM Service
    # @mock_acm
    def test_service(self):
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert acm.service == "acm"

    # Test ACM Client
    # @mock_acm
    def test_client(self):
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        for regional_client in acm.regional_clients.values():
            assert regional_client.__class__.__name__ == "ACM"

    # Test ACM Session
    # @mock_acm
    def test__get_session__(self):
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert acm.session.__class__.__name__ == "Session"

    # Test ACM Session
    # @mock_acm
    def test_audited_account(self):
        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert acm.audited_account == AWS_ACCOUNT_NUMBER

    # Test ACM List Certificates
    # @mock_acm
    def test__list_and_describe_certificates__(self):
        # Generate ACM Client
        # acm_client = client("acm", region_name=AWS_REGION)
        # Request ACM certificate
        # certificate = acm_client.request_certificate(
        #     DomainName="test.com",
        # )

        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert len(acm.certificates) == 1
        assert acm.certificates[0].arn == certificate_arn
        assert acm.certificates[0].name == certificate_name
        assert acm.certificates[0].type == certificate_type
        assert acm.certificates[0].expiration_days == 365
        assert acm.certificates[0].transparency_logging is False
        assert acm.certificates[0].region == AWS_REGION

    # Test ACM List Tags
    # @mock_acm
    def test__list_tags_for_certificate__(self):
        # Generate ACM Client
        # acm_client = client("acm", region_name=AWS_REGION)
        # Request ACM certificate
        # certificate = acm_client.request_certificate(
        #     DomainName="test.com",
        # )

        # ACM client for this test class
        audit_info = self.set_mocked_audit_info()
        acm = ACM(audit_info)
        assert len(acm.certificates) == 1
        assert acm.certificates[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
