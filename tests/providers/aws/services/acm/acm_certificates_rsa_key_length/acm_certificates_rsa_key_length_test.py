import uuid
from unittest import mock

from prowler.providers.aws.services.acm.acm_service import Certificate

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_acm_certificates_rsa_key_length:
    def test_no_acm_certificates(self):
        acm_client = mock.MagicMock
        acm_client.certificates = []

        with mock.patch(
            "prowler.providers.aws.services.acm.acm_service.ACM",
            new=acm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_rsa_key_length.acm_certificates_rsa_key_length import (
                acm_certificates_rsa_key_length,
            )

            check = acm_certificates_rsa_key_length()
            result = check.execute()

            assert len(result) == 0

    def test_acm_certificate_valid_key_length(self):
        certificate_id = str(uuid.uuid4())
        certificate_arn = f"arn:aws:acm:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:certificate/{certificate_id}"
        certificate_name = "test-certificate.com"
        certificate_type = "AMAZON_ISSUED"
        certificate_key_algorithm = "RSA_2048"

        acm_client = mock.MagicMock
        acm_client.certificates = [
            Certificate(
                arn=certificate_arn,
                id=certificate_id,
                name=certificate_name,
                type=certificate_type,
                key_algorithm=certificate_key_algorithm,
                expiration_days=365,
                transparency_logging=True,
                in_use=True,
                region=AWS_REGION,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.acm.acm_service.ACM",
            new=acm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_rsa_key_length.acm_certificates_rsa_key_length import (
                acm_certificates_rsa_key_length,
            )

            check = acm_certificates_rsa_key_length()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ACM Certificate {certificate_id} for {certificate_name} meet minimum key size requirements."
            )
            assert result[0].resource_id == certificate_id
            assert result[0].resource_arn == certificate_arn
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_acm_certificate_short_RSA_key(self):
        certificate_id = str(uuid.uuid4())
        certificate_arn = f"arn:aws:acm:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:certificate/{certificate_id}"
        certificate_name = "test-certificate.com"
        certificate_type = "AMAZON_ISSUED"
        certificate_key_algorithm = "RSA_1024"

        acm_client = mock.MagicMock
        acm_client.certificates = [
            Certificate(
                arn=certificate_arn,
                id=certificate_id,
                name=certificate_name,
                type=certificate_type,
                key_algorithm=certificate_key_algorithm,
                expiration_days=365,
                transparency_logging=False,
                in_use=True,
                region=AWS_REGION,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.acm.acm_service.ACM",
            new=acm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_rsa_key_length.acm_certificates_rsa_key_length import (
                acm_certificates_rsa_key_length,
            )

            check = acm_certificates_rsa_key_length()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ACM Certificate {certificate_id} for {certificate_name} uses RSA_1024 which is not secure enough."
            )
            assert result[0].resource_id == certificate_id
            assert result[0].resource_arn == certificate_arn
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []
