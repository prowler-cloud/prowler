from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_iam_no_expired_server_certificates_stored_test:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
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
        )
        return audit_info

    @mock_iam
    def test_no_certificates(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
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

    @mock_iam
    def test_expired_certificate(self):
        iam_client = client("iam")
        # moto creates an expired certificate by default
        cert = iam_client.upload_server_certificate(
            ServerCertificateName="certname",
            CertificateBody="certbody",
            PrivateKey="privatekey",
        )["ServerCertificateMetadata"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
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
