from boto3 import session
from mock import patch

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.lib.service.service import AWSService
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_PARTITION = "aws"
AWS_REGION = "us-east-1"


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_AWSService:
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
            audited_account_arn=AWS_ACCOUNT_ARN,
            audited_user_id=None,
            audited_partition=AWS_PARTITION,
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=[],
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    def test_AWSService_init(self):
        audit_info = self.set_mocked_audit_info()
        service = AWSService("s3", audit_info)

        assert service.audit_info == audit_info
        assert service.audited_account == AWS_ACCOUNT_NUMBER
        assert service.audited_account_arn == AWS_ACCOUNT_ARN
        assert service.audited_partition == AWS_PARTITION
        assert service.audit_resources == []
        assert service.audited_checks == []
        assert service.session == audit_info.audit_session
        assert service.service == "s3"
        assert len(service.regional_clients) == 1
        assert service.regional_clients[AWS_REGION].__class__.__name__ == "S3"
        assert service.region == AWS_REGION
        assert service.client.__class__.__name__ == "S3"
