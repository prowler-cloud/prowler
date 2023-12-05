from unittest import mock

from boto3 import client
from moto import mock_iam

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_iam_check_saml_providers_sts:
    @mock_iam
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

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_check_saml_providers_sts.iam_check_saml_providers_sts.iam_client",
                new=IAM(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_check_saml_providers_sts.iam_check_saml_providers_sts import (
                    iam_check_saml_providers_sts,
                )

                check = iam_check_saml_providers_sts()
                result = check.execute()
                assert result[0].status == "PASS"
