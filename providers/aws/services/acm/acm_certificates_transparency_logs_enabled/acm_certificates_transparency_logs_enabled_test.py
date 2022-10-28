from unittest import mock

from boto3 import client
from moto import mock_acm

AWS_REGION = "us-east-1"


class Test_acm_certificates_transparency_logs_enabled:
    @mock_acm
    def test_acm_certificate_with_logging(self):
        # Generate ACM Client
        acm_client = client("acm", region_name=AWS_REGION)
        # Request ACM certificate
        certificate = acm_client.request_certificate(
            DomainName="test.com",
            Options={"CertificateTransparencyLoggingPreference": "ENABLED"},
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.acm.acm_service import ACM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled.acm_client",
            new=ACM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import (
                acm_certificates_transparency_logs_enabled,
            )

            check = acm_certificates_transparency_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ACM Certificate for test.com has Certificate Transparency logging enabled."
            )
            assert result[0].resource_id == "test.com"
            assert result[0].resource_arn == certificate["CertificateArn"]

    @mock_acm
    def test_acm_certificate_without_logging(self):
        # Generate ACM Client
        acm_client = client("acm", region_name=AWS_REGION)
        # Request ACM certificate
        certificate = acm_client.request_certificate(
            DomainName="test.com",
            Options={"CertificateTransparencyLoggingPreference": "ENABLED"},
        )
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.acm.acm_service import ACM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled.acm_client",
            new=ACM(current_audit_info),
        ) as service_client:
            # Test Check
            from providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import (
                acm_certificates_transparency_logs_enabled,
            )

            service_client.certificates[0].transparency_logging = False
            check = acm_certificates_transparency_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ACM Certificate for test.com has Certificate Transparency logging disabled."
            )
            assert result[0].resource_id == "test.com"
            assert result[0].resource_arn == certificate["CertificateArn"]

    @mock_acm
    def test_acm_default_certificate(self):
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
            "providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled.acm_client",
            new=ACM(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import (
                acm_certificates_transparency_logs_enabled,
            )

            check = acm_certificates_transparency_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ACM Certificate for test.com has Certificate Transparency logging enabled."
            )
            assert result[0].resource_id == "test.com"
            assert result[0].resource_arn == certificate["CertificateArn"]

    @mock_acm
    def test_bad_response(self):
        mock_client = mock.MagicMock()

        with mock.patch(
            "providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled.acm_client",
            new=mock_client,
        ):
            # Test Check
            from providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import (
                acm_certificates_transparency_logs_enabled,
            )

            check = acm_certificates_transparency_logs_enabled()
            result = check.execute()

            assert len(result) == 0
