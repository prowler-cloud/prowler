from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    set_mocked_aws_provider,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
elb_arn = (
    f"arn:aws:elasticloadbalancing:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
)

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


class Test_elb_ssl_listeners_use_acm_certificate:
    @mock_aws
    def test_elb_no_balancers(self):
        from prowler.providers.aws.services.acm.acm_service import ACM
        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.elb_client",
            new=ELB(aws_mocked_provider),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate import (
                elb_ssl_listeners_use_acm_certificate,
            )

            check = elb_ssl_listeners_use_acm_certificate()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_elb_with_HTTPs_listener_imported_certificate(self):
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)
        acm = client("acm", region_name=AWS_REGION)
        certificate = acm.import_certificate(
            Certificate=CERTIFICATE.strip(),
            PrivateKey=PRIVATE_KEY.strip(),
        )

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {
                    "Protocol": "https",
                    "LoadBalancerPort": 80,
                    "InstancePort": 8080,
                    "SSLCertificateId": certificate["CertificateArn"],
                },
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        from prowler.providers.aws.services.acm.acm_service import ACM
        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.elb_client",
            new=ELB(aws_mocked_provider),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            from prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate import (
                elb_ssl_listeners_use_acm_certificate,
            )

            check = elb_ssl_listeners_use_acm_certificate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ELB my-lb has HTTPS/SSL listeners that are using certificates not managed by ACM."
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == elb_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION

    @mock_aws
    def test_elb_with_SSL_listener_imported_certificate(self):
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)
        acm = client("acm", region_name=AWS_REGION)
        certificate = acm.import_certificate(
            Certificate=CERTIFICATE.strip(),
            PrivateKey=PRIVATE_KEY.strip(),
        )

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {
                    "Protocol": "ssl",
                    "LoadBalancerPort": 80,
                    "InstancePort": 8080,
                    "SSLCertificateId": certificate["CertificateArn"],
                },
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        from prowler.providers.aws.services.acm.acm_service import ACM
        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.elb_client",
            new=ELB(aws_mocked_provider),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            from prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate import (
                elb_ssl_listeners_use_acm_certificate,
            )

            check = elb_ssl_listeners_use_acm_certificate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ELB my-lb has HTTPS/SSL listeners that are using certificates not managed by ACM."
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == elb_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION

    @mock_aws
    def test_elb_with_HTTPs_listener_ACM_certificate(self):
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)
        acm = client("acm", region_name=AWS_REGION)
        certificate = acm.request_certificate(DomainName="www.example.com")

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {
                    "Protocol": "https",
                    "LoadBalancerPort": 80,
                    "InstancePort": 8080,
                    "SSLCertificateId": certificate["CertificateArn"],
                },
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        from prowler.providers.aws.services.acm.acm_service import ACM
        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.elb_client",
            new=ELB(aws_mocked_provider),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            from prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate import (
                elb_ssl_listeners_use_acm_certificate,
            )

            check = elb_ssl_listeners_use_acm_certificate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ELB my-lb HTTPS/SSL listeners are using certificates managed by ACM."
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == elb_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION

    @mock_aws
    def test_elb_with_SSL_listener_ACM_certificate(self):
        elb = client("elb", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)
        acm = client("acm", region_name=AWS_REGION)
        certificate = acm.request_certificate(DomainName="www.example.com")

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {
                    "Protocol": "ssl",
                    "LoadBalancerPort": 80,
                    "InstancePort": 8080,
                    "SSLCertificateId": certificate["CertificateArn"],
                },
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        from prowler.providers.aws.services.acm.acm_service import ACM
        from prowler.providers.aws.services.elb.elb_service import ELB

        aws_mocked_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_mocked_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.elb_client",
            new=ELB(aws_mocked_provider),
        ), mock.patch(
            "prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate.acm_client",
            new=ACM(aws_mocked_provider),
        ):
            from prowler.providers.aws.services.elb.elb_ssl_listeners_use_acm_certificate.elb_ssl_listeners_use_acm_certificate import (
                elb_ssl_listeners_use_acm_certificate,
            )

            check = elb_ssl_listeners_use_acm_certificate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ELB my-lb HTTPS/SSL listeners are using certificates managed by ACM."
            )
            assert result[0].resource_id == "my-lb"
            assert result[0].resource_arn == elb_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION
