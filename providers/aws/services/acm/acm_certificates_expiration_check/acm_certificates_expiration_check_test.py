from unittest import mock

from boto3 import client
from moto import mock_acm

AWS_REGION = "us-east-1"


class Test_acm_certificates_expiration_check:
    @mock_acm
    def test_acm_certificate_expirated(self):
        # Generate ACM Client
        acm_client = client("acm", region_name=AWS_REGION)
        # Request ACM certificate
        certificate = acm_client.request_certificate(
            DomainName="test.com",
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.acm.acm_service import ACM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.acm.acm_certificates_expiration_check.acm_certificates_expiration_check.acm_client",
            new=ACM(current_audit_info),
        ) as service_client:
            # Test Check
            from providers.aws.services.acm.acm_certificates_expiration_check.acm_certificates_expiration_check import (
                acm_certificates_expiration_check,
            )

            service_client.certificates[0].expiration_days = 5
            check = acm_certificates_expiration_check()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "test.com"
            assert result[0].resource_arn == certificate["CertificateArn"]

    @mock_acm
    def test_acm_certificate_not_expirated(self):
        # Generate ACM Client
        acm_client = client("acm", region_name=AWS_REGION)
        # Request ACM certificate
        certificate = acm_client.request_certificate(
            DomainName="test.com",
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.acm.acm_service import ACM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.acm.acm_certificates_expiration_check.acm_certificates_expiration_check.acm_client",
            new=ACM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.acm.acm_certificates_expiration_check.acm_certificates_expiration_check import (
                acm_certificates_expiration_check,
            )

            check = acm_certificates_expiration_check()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "test.com"
            assert result[0].resource_arn == certificate["CertificateArn"]
