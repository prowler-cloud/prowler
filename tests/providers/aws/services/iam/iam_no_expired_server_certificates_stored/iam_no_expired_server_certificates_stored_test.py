from re import search
from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_no_expired_server_certificates_stored_test:
    @mock_iam
    def test_no_certificates(self):
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_no_expired_server_certificates_stored.iam_no_expired_server_certificates_stored.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_no_expired_server_certificates_stored.iam_no_expired_server_certificates_stored import (
                iam_no_expired_server_certificates_stored,
            )

            check = iam_no_expired_server_certificates_stored()
            result = check.execute()

            assert len(result) == 0

    @mock_iam
    def test_expired_certificate(self):
        iam_client = client("iam")
        # moto creates an expired certificate by default
        cert = iam_client.upload_server_certificate(
            ServerCertificateName="certname",
            CertificateBody="certbody",
            PrivateKey="privatekey",
        )["ServerCertificateMetadata"]
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_no_expired_server_certificates_stored.iam_no_expired_server_certificates_stored.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_no_expired_server_certificates_stored.iam_no_expired_server_certificates_stored import (
                iam_no_expired_server_certificates_stored,
            )

            check = iam_no_expired_server_certificates_stored()
            result = check.execute()

            assert len(result) == 1

            assert result[0].status == "FAIL"
            assert search(
                "IAM Certificate certname has expired", result[0].status_extended
            )
            assert result[0].resource_id == cert["ServerCertificateId"]
            assert result[0].resource_arn == cert["Arn"]
