from mock import patch

from prowler.providers.aws.lib.service.service import AWSService
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_AWSService:
    def test_AWSService_init(self):
        service_name = "s3"
        audit_info = set_mocked_aws_audit_info()
        service = AWSService(service_name, audit_info)

        assert service.audit_info == audit_info
        assert service.audited_account == AWS_ACCOUNT_NUMBER
        assert service.audited_account_arn == AWS_ACCOUNT_ARN
        assert service.audited_partition == AWS_COMMERCIAL_PARTITION
        assert service.audit_resources == []
        assert service.audited_checks == []
        assert service.session == audit_info.audit_session
        assert service.service == service_name
        assert len(service.regional_clients) == 1
        assert (
            service.regional_clients[AWS_REGION_US_EAST_1].__class__.__name__
            == service_name.upper()
        )
        assert service.region == AWS_REGION_US_EAST_1
        assert service.client.__class__.__name__ == service_name.upper()

    def test_AWSService_init_global_service(self):
        service_name = "cloudfront"
        audit_info = set_mocked_aws_audit_info()
        service = AWSService(service_name, audit_info, global_service=True)

        assert service.audit_info == audit_info
        assert service.audited_account == AWS_ACCOUNT_NUMBER
        assert service.audited_account_arn == AWS_ACCOUNT_ARN
        assert service.audited_partition == AWS_COMMERCIAL_PARTITION
        assert service.audit_resources == []
        assert service.audited_checks == []
        assert service.session == audit_info.audit_session
        assert service.service == service_name
        assert not hasattr(service, "regional_clients")
        assert service.region == AWS_REGION_US_EAST_1
        assert service.client.__class__.__name__ == "CloudFront"

    def test_AWSService_set_failed_check(self):

        AWSService.failed_checks.clear()

        check_id = "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"
        arn = "arn:aws:ec2:eu-central-1:123456789:security-group/sg-12345678"

        assert (check_id, arn) not in AWSService.failed_checks

        AWSService.set_failed_check(check_id, arn)

        assert (check_id, arn) in AWSService.failed_checks

    def test_AWSService_is_failed_check(self):

        AWSService.failed_checks.clear()

        check_id = "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"
        arn = "arn:aws:ec2:eu-central-1:123456789:security-group/sg-12345678"

        assert not AWSService.is_failed_check(check_id, arn)

        AWSService.set_failed_check(check_id, arn)

        assert AWSService.is_failed_check(check_id, arn)
        assert not AWSService.is_failed_check(
            check_id,
            "arn:aws:ec2:eu-central-1:123456789:security-group/sg-87654321",
        )
