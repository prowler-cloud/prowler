from unittest import mock

from boto3 import client
from moto import mock_acm

from providers.aws.lib.audit_info.audit_info import current_audit_info
from providers.aws.services.acm.acm_service import ACM


class Test_acm_certificate_without_logging:
    @mock_acm
    def test_acm_certificate_without_logging(self):
        # Generate ACM Client
        acm_client = client("acm")
        # Request ACM certificate
        acm_client.request_certificate(
            DomainName="test.com",
            Options={"CertificateTransparencyLoggingPreference": "DISABLED"},
        )
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
            assert result[0].status == "FAIL"

    @mock_acm
    def test_acm_certificate_without_logging(self):
        # Generate ACM Client
        acm_client = client("acm")
        # Request ACM certificate
        acm_client.request_certificate(
            DomainName="test.com",
            Options={"CertificateTransparencyLoggingPreference": "ENABLED"},
        )
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

    @mock_acm
    def test_acm_default_certificate(self):
        # Generate ACM Client
        acm_client = client("acm")
        # Request ACM certificate
        acm_client.request_certificate(
            DomainName="test.com",
        )
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

    @mock_acm
    def test_bad_response(self):
        mock_client = mock.MagicMock()
        mock_client.credential_report = None
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
