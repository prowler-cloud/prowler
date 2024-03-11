from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_iam_no_expired_server_certificates_stored_test:
    @mock_aws
    def test_no_certificates(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_expired_server_certificates_stored.iam_no_expired_server_certificates_stored.iam_client",
                new=IAM(audit_info),
            ):
                from prowler.providers.aws.services.iam.iam_no_expired_server_certificates_stored.iam_no_expired_server_certificates_stored import (
                    iam_no_expired_server_certificates_stored,
                )

                check = iam_no_expired_server_certificates_stored()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_expired_certificate(self):
        iam_client = client("iam")
        # moto creates an expired certificate by default
        cert = iam_client.upload_server_certificate(
            ServerCertificateName="certname",
            CertificateBody="certbody",
            PrivateKey="privatekey",
        )["ServerCertificateMetadata"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_expired_server_certificates_stored.iam_no_expired_server_certificates_stored.iam_client",
                new=IAM(audit_info),
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
