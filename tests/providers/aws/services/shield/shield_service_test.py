import botocore
from boto3 import session
from mock import patch
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.shield.shield_service import Shield
from prowler.providers.common.models import Audit_Metadata

# Mock Test Region
AWS_REGION = "eu-west-1"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListProtections":
        return {
            "Protections": [
                {
                    "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111",
                    "Name": "Protection for CloudFront distribution",
                    "ResourceArn": f"arn:aws:cloudfront::{DEFAULT_ACCOUNT_ID}:distribution/E198WC25FXOWY8",
                }
            ]
        }
    if operation_name == "GetSubscriptionState":
        return {"SubscriptionState": "ACTIVE"}

    return make_api_call(self, operation_name, kwarg)


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_Shield_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=DEFAULT_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test Shield Service
    def test_service(self):
        # Shield client for this test class
        audit_info = self.set_mocked_audit_info()
        shield = Shield(audit_info)
        assert shield.service == "shield"

    # Test Shield Client
    def test_client(self):
        # Shield client for this test class
        audit_info = self.set_mocked_audit_info()
        shield = Shield(audit_info)
        assert shield.client.__class__.__name__ == "Shield"

    # Test Shield Session
    def test__get_session__(self):
        # Shield client for this test class
        audit_info = self.set_mocked_audit_info()
        shield = Shield(audit_info)
        assert shield.session.__class__.__name__ == "Session"

    def test__get_subscription_state__(self):
        # Shield client for this test class
        audit_info = self.set_mocked_audit_info()
        shield = Shield(audit_info)
        assert shield.enabled

    def test__list_protections__(self):
        # Shield client for this test class
        audit_info = self.set_mocked_audit_info()
        shield = Shield(audit_info)
        protection_id = "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
        protection_name = "Protection for CloudFront distribution"
        cloudfront_distribution_id = "E198WC25FXOWY8"
        resource_arn = (
            f"arn:aws:cloudfront::{DEFAULT_ACCOUNT_ID}:distribution/{cloudfront_distribution_id}",
        )

        assert shield.protections
        assert len(shield.protections) == 1
        assert shield.protections[protection_id]
        assert shield.protections[protection_id].id == protection_id
        assert shield.protections[protection_id].name == protection_name
        assert not shield.protections[protection_id].protection_arn
        assert not shield.protections[protection_id].resource_arn == resource_arn
