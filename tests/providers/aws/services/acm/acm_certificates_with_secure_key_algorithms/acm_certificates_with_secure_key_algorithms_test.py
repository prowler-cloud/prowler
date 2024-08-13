import uuid
from unittest import mock

from prowler.providers.aws.services.acm.acm_service import Certificate

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_acm_certificates_with_secure_key_algorithms:
    def test_no_acm_certificates(self):
        acm_client = mock.MagicMock
        acm_client.certificates = []

        with mock.patch(
            "prowler.providers.aws.services.acm.acm_service.ACM",
            new=acm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_with_secure_key_algorithms.acm_certificates_with_secure_key_algorithms import (
                acm_certificates_with_secure_key_algorithms,
            )

            check = acm_certificates_with_secure_key_algorithms()
            result = check.execute()

            assert len(result) == 0

    def test_acm_certificate_secure_algorithm(self):
        certificate_id = str(uuid.uuid4())
        certificate_arn = f"arn:aws:acm:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:certificate/{certificate_id}"
        certificate_name = "test-certificate.com"
        certificate_type = "AMAZON_ISSUED"
        certificate_key_algorithm = "RSA-2048"

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

        acm_client.audit_config = {"insecure_algorithm": ["RSA-1024"]}

        with mock.patch(
            "prowler.providers.aws.services.acm.acm_service.ACM",
            new=acm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_with_secure_key_algorithms.acm_certificates_with_secure_key_algorithms import (
                acm_certificates_with_secure_key_algorithms,
            )

            check = acm_certificates_with_secure_key_algorithms()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ACM Certificate {certificate_id} for {certificate_name} uses a secure key algorithm ({certificate_key_algorithm})."
            )
            assert result[0].resource_id == certificate_id
            assert result[0].resource_arn == certificate_arn
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_acm_certificate_insecure_algorithm(self):
        certificate_id = str(uuid.uuid4())
        certificate_arn = f"arn:aws:acm:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:certificate/{certificate_id}"
        certificate_name = "test-certificate.com"
        certificate_type = "AMAZON_ISSUED"
        certificate_key_algorithm = "RSA-1024"

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

        acm_client.audit_config = {"insecure_algorithm": ["RSA-1024"]}

        with mock.patch(
            "prowler.providers.aws.services.acm.acm_service.ACM",
            new=acm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_with_secure_key_algorithms.acm_certificates_with_secure_key_algorithms import (
                acm_certificates_with_secure_key_algorithms,
            )

            check = acm_certificates_with_secure_key_algorithms()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ACM Certificate {certificate_id} for {certificate_name} does not use a secure key algorithm ({certificate_key_algorithm})."
            )
            assert result[0].resource_id == certificate_id
            assert result[0].resource_arn == certificate_arn
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []
