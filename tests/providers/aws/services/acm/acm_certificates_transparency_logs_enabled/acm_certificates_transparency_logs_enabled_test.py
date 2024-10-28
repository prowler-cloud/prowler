import datetime
from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.acm.acm_service import ACM
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListCertificates":
        return {
            "CertificateSummaryList": [
                {
                    "CertificateArn": "arn:aws:acm:eu-west-1:123456789012:certificate/test-logging",
                    "DomainName": "test-logging.com",
                    "CertificateType": "AMAZON_ISSUED",
                    "KeyAlgorithm": "RSA_2048",
                    "Type": "AMAZON_ISSUED",
                    "InUse": True,
                    "NotAfter": datetime.datetime.now() + datetime.timedelta(days=4),
                }
            ]
        }
    if operation_name == "DescribeCertificate":
        return {
            "Certificate": {
                "Options": {"CertificateTransparencyLoggingPreference": "ENABLED"},
            }
        }

    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "ListCertificates":
        return {
            "CertificateSummaryList": [
                {
                    "CertificateArn": "arn:aws:acm:eu-west-1:123456789012:certificate/test-no-logging",
                    "DomainName": "test-no-logging.com",
                    "CertificateType": "AMAZON_ISSUED",
                    "KeyAlgorithm": "RSA_2048",
                    "Type": "AMAZON_ISSUED",
                    "InUse": True,
                    "NotAfter": datetime.datetime.now() - datetime.timedelta(days=4),
                }
            ]
        }
    if operation_name == "DescribeCertificate":
        return {
            "Certificate": {
                "Options": {"CertificateTransparencyLoggingPreference": "DISABLED"},
            }
        }

    return make_api_call(self, operation_name, kwarg)


CERTIFICATE = """
-----BEGIN CERTIFICATE-----
MIIEUDCCAjgCCQDfXZHMio+6oDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJH
QjESMBAGA1UECAwJQmVya3NoaXJlMQ8wDQYDVQQHDAZTbG91Z2gxEzARBgNVBAoM
Ck1vdG9TZXJ2ZXIxCzAJBgNVBAsMAlFBMQ0wCwYDVQQDDARNb3RvMB4XDTE5MTAy
MTEzMjczMVoXDTQ5MTIzMTEzMjczNFowcTELMAkGA1UEBhMCR0IxEjAQBgNVBAgM
CUJlcmtzaGlyZTEPMA0GA1UEBwwGU2xvdWdoMRMwEQYDVQQKDApNb3RvU2VydmVy
MRMwEQYDVQQLDApPcGVyYXRpb25zMRMwEQYDVQQDDAoqLm1vdG8uY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzC/oBkzwiIBEceSC/tSD7hkqs8AW
niDXbMgAQE9oxUxtkFESxiNa+EbAMLBFtBkPRvc3iKXh/cfLo7yP8VdqEIDmJCB/
3T3ljjmrCMwquxYgZWMShnXZV0YfC19Vzq/gFpiyoaI2SI5NOFlfwhs5hFacTGkf
vpjJvf6HnrNJ7keQR+oGJNf7jVaCgOVdJ4lt7+98YDVde7jLx1DN+QbvViJQl60n
K3bmfuLiiw8154Eyi9DOcJE8AB+W7KpPdrmbPisR1EiqY0i0L62ZixN0rPi5hHF+
ozwURL1axcmLjlhIFi8YhBCNcY6ThE7jrqgLIq1n6d8ezRxjDKmqfH1spQIDAQAB
MA0GCSqGSIb3DQEBCwUAA4ICAQAOwvJjY1cLIBVGCDPkkxH4xCP6+QRdm7bqF7X5
DNZ70YcJ27GldrEPmKX8C1RvkC4oCsaytl8Hlw3ZcS1GvwBxTVlnYIE6nLPPi1ix
LvYYgoq+Mjk/2XPCnU/6cqJhb5INskg9s0o15jv27cUIgWVMnj+d5lvSiy1HhdYM
wvuQzXELjhe/rHw1/BFGaBV2vd7einUQwla50UZLcsj6FwWSIsv7EB4GaY/G0XqC
Mai2PltBgBPFqsZo27uBeVfxqMZtwAQlr4iWwWZm1haDy6D4GFCSR8E/gtlyhiN4
MOk1cmr9PSOMB3CWqKjkx7lPMOQT/f+gxlCnupNHsHcZGvQV4mCPiU+lLwp+8z/s
bupQwRvu1SwSUD2rIsVeUuSP3hbMcfhiZA50lenQNApimgrThdPUoFXi07FUdL+F
1QCk6cvA48KzGRo+bPSfZQusj51k/2+hl4sHHZdWg6mGAIY9InMKmPDE4VzM8hro
fr2fJLqKQ4h+xKbEYnvPEPttUdJbvUgr9TKKVw+m3lmW9SktzE5KtvWvN6daTj9Z
oHDJkOyko3uyTzk+HwWDC/pQ2cC+iF1MjIHi72U9ibObSODg/d9cMH3XJTnZ9W3+
He9iuH4dJpKnVjnJ5NKt7IOrPHID77160hpwF1dim22ZRp508eYapRzgawPMpCcd
a6YipQ==
-----END CERTIFICATE-----
        """

PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAzC/oBkzwiIBEceSC/tSD7hkqs8AWniDXbMgAQE9oxUxtkFES
xiNa+EbAMLBFtBkPRvc3iKXh/cfLo7yP8VdqEIDmJCB/3T3ljjmrCMwquxYgZWMS
hnXZV0YfC19Vzq/gFpiyoaI2SI5NOFlfwhs5hFacTGkfvpjJvf6HnrNJ7keQR+oG
JNf7jVaCgOVdJ4lt7+98YDVde7jLx1DN+QbvViJQl60nK3bmfuLiiw8154Eyi9DO
cJE8AB+W7KpPdrmbPisR1EiqY0i0L62ZixN0rPi5hHF+ozwURL1axcmLjlhIFi8Y
hBCNcY6ThE7jrqgLIq1n6d8ezRxjDKmqfH1spQIDAQABAoIBAECa588WiQSnkQB4
TPpUQ2oSjHBTVtSxj3fb0DiI552FkSUYgdgvV5k2yZieLW/Ofgb2MZwK4HZrwQMN
pn22KtkN78N+hPZ7nyZhGLyv3NVVKurpbfMdVqdGiIwQnhXHkB+WMO7zZDmQzN4H
aUUBWDGHNez3VhP4Q9zZrA+Kqtm5OYmkDQYO6LqR+OQmqmLEeJOsbR9EUXDuhd5O
CyWkBwZP5JcmP985hZ7dGTZJ9ehFLYq6i6ZLmuSkt6QS/jf+AdLjd6b2b326CUwJ
xEf3ZwQ9b+BPZ+gCx91FsooRqa3NbFhvGJ34sN25xzppa5+IDDk5XZnXJugwq5Sg
t5f07AECgYEA/G3+GIXlnyLwOksFFHQp1yZIlXxeGhVZyDwSHkXcAwRnTWZHHftr
fZ2TQkyYxsySx/pP6PUHQDwhZKFSLIpc2Di2ZIUPZSNYrzEqCZIBTO9+2DBshjs6
2tUyvpD68lZsQpjipD6wNF+308Px5hAg5mKr5IstHCcXkJcxa3v5kVMCgYEAzxM8
PbGQmSNalcO1cBcj/f7sbEbJOtdb94ig8KRc8ImL3ZM9dJOugqc0EchMzUzFD4H/
CjaC25CjxfBZSxV+0D6spUeLKogdwoyAM08/ZwD6BuMKZlbim84wV0VZBXjSaihq
qdaLnx0qC7/DPLf2zQfWkJCcqvPzMf+W6PgQcycCgYA3VW0jtwY0shXy0UsVxrj9
Ppkem5qNIS0DJZfbJvkpeCek4cypF9niOU50dBHxUhrC12345O1n+UZgprQ6q0Ha
6+OfeUN8qhjgnmhWnLjIQp+NiF/htM4b9iwfdexsfuFQX+8ejddWQ70qIIPAKLzt
g6eme5Ox3ifePCZLJ2v3nQKBgFBeitb2/8Qv8IyH9PeYQ6PlOSWdI6TuyQb9xFkh
seC5wcsxxnxkhSq4coEkWIql7SXjsnToS0mkjavZaQ63PQzeBmvvpJfRVJuZpHhF
nboAqwnZPMQTnMgT8rcsdyykhCYnoZ5hYrdSvmro9oGudN+G10QsnGHNZOpW5N9u
yBOpAoGASb5aNQU9QFT8kyxZB+nKAuh6efa6HNMXMdEoYD9VOm0zPMRtorZdX4s4
nYctHiIUmVAIXtkG0tR+cOelv2qKR5EfOo3HZtaP+fbOd0IykoZcbQJpc3PwDcCq
WgkRhN4dCVYD3ZXFYlUrCoDca7JE1KxmIbrlVSAaYilkt7UB3Qk=
-----END RSA PRIVATE KEY-----
        """


class Test_acm_certificates_transparency_logs_enabled:
    @mock_aws
    def test_no_acm_certificates(self):
        client("acm", region_name=AWS_REGION_EU_WEST_1)

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import (
                acm_certificates_transparency_logs_enabled,
            )

            check = acm_certificates_transparency_logs_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_unused_acm_certificate(self):
        acm = client("acm", region_name=AWS_REGION_EU_WEST_1)
        acm.import_certificate(
            Certificate=CERTIFICATE.strip(),
            PrivateKey=PRIVATE_KEY.strip(),
        )["CertificateArn"]

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_mocked_provider._scan_unused_services = False
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import (
                acm_certificates_transparency_logs_enabled,
            )

            check = acm_certificates_transparency_logs_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_acm_certificate_with_logging(self):
        client("acm", region_name=AWS_REGION_EU_WEST_1)

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import (
                acm_certificates_transparency_logs_enabled,
            )

            check = acm_certificates_transparency_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ACM Certificate test-logging for test-logging.com has Certificate Transparency logging enabled."
            )
            assert result[0].resource_id == "test-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:acm:eu-west-1:123456789012:certificate/test-logging"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_acm_certificate_without_logging(self):
        client("acm", region_name=AWS_REGION_EU_WEST_1)

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import (
                acm_certificates_transparency_logs_enabled,
            )

            check = acm_certificates_transparency_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ACM Certificate test-no-logging for test-no-logging.com has Certificate Transparency logging disabled."
            )
            assert result[0].resource_id == "test-no-logging"
            assert (
                result[0].resource_arn
                == "arn:aws:acm:eu-west-1:123456789012:certificate/test-no-logging"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_acm_certificate_imported(self):
        acm = client("acm", region_name=AWS_REGION_EU_WEST_1)
        certificate_arn = acm.import_certificate(
            Certificate=CERTIFICATE.strip(),
            PrivateKey=PRIVATE_KEY.strip(),
        )["CertificateArn"]
        certificate_id = certificate_arn.split("/")[-1]
        certificate = acm.describe_certificate(CertificateArn=certificate_arn)

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.acm.acm_certificates_transparency_logs_enabled.acm_certificates_transparency_logs_enabled import (
                acm_certificates_transparency_logs_enabled,
            )

            check = acm_certificates_transparency_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ACM Certificate {certificate_id} for {certificate['Certificate']['DomainName']} is imported."
            )
            assert result[0].resource_id == certificate_id
            assert result[0].resource_arn == certificate_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
