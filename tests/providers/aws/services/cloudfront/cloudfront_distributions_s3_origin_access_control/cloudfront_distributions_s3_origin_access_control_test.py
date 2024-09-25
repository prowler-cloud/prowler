from unittest import mock

from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    Distribution,
    Origin,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER

DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)
REGION = "eu-west-1"


class Test_cloudfront_distributions_s3_origin_access_control:
    def test_no_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {}
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_access_control.cloudfront_distributions_s3_origin_access_control import (
                cloudfront_distributions_s3_origin_access_control,
            )

            check = cloudfront_distributions_s3_origin_access_control()
            result = check.execute()

            assert len(result) == 0

    def test_no_s3_origin_distributions(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id="string",
                        domain_name="string",
                        origin_protocol_policy="https-only",
                        origin_ssl_protocols=["TLSv1", "TLSv1.1"],
                        s3_origin_config={},
                    ),
                ],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_access_control.cloudfront_distributions_s3_origin_access_control import (
                cloudfront_distributions_s3_origin_access_control,
            )

            check = cloudfront_distributions_s3_origin_access_control()
            result = check.execute()

            assert len(result) == 0

    def test_distribution_using_origin_access_control(self):
        cloudfront_client = mock.MagicMock
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id="string",
                        domain_name="string",
                        origin_protocol_policy="https-only",
                        origin_ssl_protocols=["TLSv1", "TLSv1.1"],
                        origin_access_control="EXAMPLE-OAC-ID",
                        s3_origin_config={
                            "OriginAccessIdentity": "origin-access-identity/cloudfront/EXAMPLE-OAI-ID"
                        },
                    ),
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_access_control.cloudfront_distributions_s3_origin_access_control import (
                cloudfront_distributions_s3_origin_access_control,
            )

            check = cloudfront_distributions_s3_origin_access_control()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is using origin access control (OAC) for S3 origins."
            )
            assert result[0].resource_tags == []

    def test_distribution_not_using_origin_access_control(self):
        cloudfront_client = mock.MagicMock
        id = "EXAMPLE-OAC-ID"
        cloudfront_client.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                origins=[
                    Origin(
                        id=id,
                        domain_name="string",
                        origin_protocol_policy="https-only",
                        origin_ssl_protocols=["TLSv1", "TLSv1.1"],
                        origin_access_control="",
                        s3_origin_config={
                            "OriginAccessIdentity": "origin-access-identity/cloudfront/EXAMPLE-OAI-ID"
                        },
                    ),
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_service.CloudFront",
            new=cloudfront_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_access_control.cloudfront_distributions_s3_origin_access_control import (
                cloudfront_distributions_s3_origin_access_control,
            )

            check = cloudfront_distributions_s3_origin_access_control()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} is not using origin access control (OAC) in S3 origins {id}."
            )
            assert result[0].resource_tags == []
