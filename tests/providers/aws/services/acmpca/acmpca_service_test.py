from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.acmpca.acmpca_service import (
    ACMPCA,
    CertificateAuthority,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CA_ID = "12345678-1234-1234-1234-123456789012"
CA_ARN = f"arn:aws:acm-pca:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:certificate-authority/{CA_ID}"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListCertificateAuthorities":
        return {
            "CertificateAuthorities": [
                {
                    "Arn": CA_ARN,
                    "Status": "ACTIVE",
                    "Type": "SUBORDINATE",
                    "UsageMode": "GENERAL_PURPOSE",
                    "CertificateAuthorityConfiguration": {
                        "KeyAlgorithm": "ML_DSA_65",
                        "SigningAlgorithm": "ML_DSA_65",
                    },
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_ACMPCA_Service:
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        acmpca = ACMPCA(aws_provider)
        assert acmpca.service == "acm-pca"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_list_certificate_authorities(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        acmpca = ACMPCA(aws_provider)
        assert len(acmpca.certificate_authorities) == 1
        ca = acmpca.certificate_authorities[CA_ARN]
        assert isinstance(ca, CertificateAuthority)
        assert ca.id == CA_ID
        assert ca.region == AWS_REGION_US_EAST_1
        assert ca.status == "ACTIVE"
        assert ca.type == "SUBORDINATE"
        assert ca.key_algorithm == "ML_DSA_65"
        assert ca.signing_algorithm == "ML_DSA_65"
