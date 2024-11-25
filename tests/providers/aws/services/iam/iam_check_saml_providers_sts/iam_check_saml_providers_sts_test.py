from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListSAMLProviderTags":
        return {
            "Tags": [
                {"Key": "Name", "Value": "test"},
                {"Key": "Owner", "Value": "test"},
            ]
        }
    return orig(self, operation_name, kwarg)


class Test_iam_check_saml_providers_sts:
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_iam_check_saml_providers_sts(self):
        iam_client = client("iam")
        xml_template = r"""<EntityDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="loadbalancer-9.siroe.com">
    <SPSSODescriptor
        AuthnRequestsSigned="false"
        WantAssertionsSigned="false"
        protocolSupportEnumeration=
            "urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>
MIICYDCCAgqgAwIBAgICBoowDQYJKoZIhvcNAQEEBQAwgZIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
EwpDYWxpZm9ybmlhMRQwEgYDVQQHEwtTYW50YSBDbGFyYTEeMBwGA1UEChMVU3VuIE1pY3Jvc3lz
dGVtcyBJbmMuMRowGAYDVQQLExFJZGVudGl0eSBTZXJ2aWNlczEcMBoGA1UEAxMTQ2VydGlmaWNh
dGUgTWFuYWdlcjAeFw0wNjExMDIxOTExMzRaFw0xMDA3MjkxOTExMzRaMDcxEjAQBgNVBAoTCXNp
cm9lLmNvbTEhMB8GA1UEAxMYbG9hZGJhbGFuY2VyLTkuc2lyb2UuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCjOwa5qoaUuVnknqf5pdgAJSEoWlvx/jnUYbkSDpXLzraEiy2UhvwpoBgB
EeTSUaPPBvboCItchakPI6Z/aFdH3Wmjuij9XD8r1C+q//7sUO0IGn0ORycddHhoo0aSdnnxGf9V
tREaqKm9dJ7Yn7kQHjo2eryMgYxtr/Z5Il5F+wIDAQABo2AwXjARBglghkgBhvhCAQEEBAMCBkAw
DgYDVR0PAQH/BAQDAgTwMB8GA1UdIwQYMBaAFDugITflTCfsWyNLTXDl7cMDUKuuMBgGA1UdEQQR
MA+BDW1hbGxhQHN1bi5jb20wDQYJKoZIhvcNAQEEBQADQQB/6DOB6sRqCZu2OenM9eQR0gube85e
nTTxU4a7x1naFxzYXK1iQ1vMARKMjDb19QEJIEJKZlDK4uS7yMlf1nFS
                    </X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
</EntityDescriptor>"""
        saml_provider_name = "test"
        iam_client.create_saml_provider(
            SAMLMetadataDocument=xml_template, Name=saml_provider_name
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_check_saml_providers_sts.iam_check_saml_providers_sts.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_check_saml_providers_sts.iam_check_saml_providers_sts import (
                    iam_check_saml_providers_sts,
                )

                check = iam_check_saml_providers_sts()
                result = check.execute()
                assert result[0].status == "PASS"
                assert result[0].resource_id == saml_provider_name
                assert (
                    result[0].resource_arn
                    == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:saml-provider/{saml_provider_name}"
                )
                assert result[0].resource_tags == [
                    {"Key": "Name", "Value": "test"},
                    {"Key": "Owner", "Value": "test"},
                ]
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].status_extended
                    == f"SAML Provider {saml_provider_name} has been found."
                )

    @mock_aws
    def test_iam_check_saml_providers_sts_no_saml_providers(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_check_saml_providers_sts.iam_check_saml_providers_sts.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_check_saml_providers_sts.iam_check_saml_providers_sts import (
                    iam_check_saml_providers_sts,
                )

                check = iam_check_saml_providers_sts()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert result[0].resource_id == "123456789012"
                assert result[0].resource_arn == "arn:aws:iam::123456789012:root"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].status_extended == "No SAML Providers found."
