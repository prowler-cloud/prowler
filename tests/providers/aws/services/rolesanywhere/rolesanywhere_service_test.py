from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.rolesanywhere.rolesanywhere_service import (
    RolesAnywhere,
    TrustAnchor,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

TA_ID = "11111111-2222-3333-4444-555555555555"
TA_ARN = f"arn:aws:rolesanywhere:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trust-anchor/{TA_ID}"
PCA_ARN = f"arn:aws:acm-pca:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:certificate-authority/abc"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListTrustAnchors":
        return {
            "trustAnchors": [
                {
                    "trustAnchorArn": TA_ARN,
                    "trustAnchorId": TA_ID,
                    "name": "pqc-trust",
                    "enabled": True,
                    "source": {
                        "sourceType": "AWS_ACM_PCA",
                        "sourceData": {"acmPcaArn": PCA_ARN},
                    },
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_RolesAnywhere_Service:
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rolesanywhere = RolesAnywhere(aws_provider)
        assert rolesanywhere.service == "rolesanywhere"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_list_trust_anchors(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        rolesanywhere = RolesAnywhere(aws_provider)
        assert len(rolesanywhere.trust_anchors) == 1
        ta = rolesanywhere.trust_anchors[TA_ARN]
        assert isinstance(ta, TrustAnchor)
        assert ta.id == TA_ID
        assert ta.name == "pqc-trust"
        assert ta.enabled is True
        assert ta.source_type == "AWS_ACM_PCA"
        assert ta.acm_pca_arn == PCA_ARN
        assert ta.region == AWS_REGION_US_EAST_1
