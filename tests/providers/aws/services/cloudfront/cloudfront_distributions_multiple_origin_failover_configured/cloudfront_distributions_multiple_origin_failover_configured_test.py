from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_cloudfront_distributions_multiple_origin_failover_configured:
    @mock_aws
    def test_no_distributions(self):
        from prowler.providers.aws.services.cloudfront.cloudfront_service import (
            CloudFront,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudfront.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_client",
                new=CloudFront(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudfront.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_distributions_multiple_origin_failover_configured import (
                    cloudfront_distributions_multiple_origin_failover_configured,
                )

                check = cloudfront_distributions_multiple_origin_failover_configured()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_1_distribution_origin_failover(self):
        cloudfront_client = client("cloudfront", region_name=AWS_REGION_US_EAST_1)

        # Crear una distribución de CloudFront simulada
        distribution_config = {
            "CallerReference": "test-distribution",
            "Comment": "test distribution",
            "Enabled": True,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "1",
                        "DomainName": "example.com",
                    },
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "1",
                "ViewerProtocolPolicy": "allow-all",
            },
        }

        response = cloudfront_client.create_distribution(
            DistributionConfig=distribution_config
        )
        distribution_id = response["Distribution"]["Id"]
        distribution_arn = response["Distribution"]["ARN"]

        from prowler.providers.aws.services.cloudfront.cloudfront_service import (
            CloudFront,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudfront.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_client",
                new=CloudFront(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudfront.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_distributions_multiple_origin_failover_configured import (
                    cloudfront_distributions_multiple_origin_failover_configured,
                )

                check = cloudfront_distributions_multiple_origin_failover_configured()
                result = check.execute()

                assert len(result) == 1
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_arn == distribution_arn
                assert result[0].resource_id == distribution_id
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"CloudFront Distribution {distribution_id} does not have an origin group with two or more origins."
                )

    @mock_aws
    def test_2_distribution_origin_failover(self):
        cloudfront_client = client("cloudfront", region_name=AWS_REGION_US_EAST_1)

        # Crear una distribución de CloudFront simulada
        distribution_config = {
            "CallerReference": "test-distribution",
            "Comment": "test distribution",
            "Enabled": True,
            "Origins": {
                "Quantity": 2,
                "Items": [
                    {
                        "Id": "1",
                        "DomainName": "example.com",
                    },
                    {
                        "Id": "2",
                        "DomainName": "example2.com",
                    },
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "1",
                "ViewerProtocolPolicy": "allow-all",
            },
        }

        response = cloudfront_client.create_distribution(
            DistributionConfig=distribution_config
        )
        distribution_id = response["Distribution"]["Id"]
        distribution_arn = response["Distribution"]["ARN"]

        from prowler.providers.aws.services.cloudfront.cloudfront_service import (
            CloudFront,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudfront.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_client",
                new=CloudFront(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudfront.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_distributions_multiple_origin_failover_configured import (
                    cloudfront_distributions_multiple_origin_failover_configured,
                )

                check = cloudfront_distributions_multiple_origin_failover_configured()
                result = check.execute()

                assert len(result) == 1
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_arn == distribution_arn
                assert result[0].resource_id == distribution_id
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"CloudFront Distribution {distribution_id} has an origin group with two or more origins."
                )

    @mock_aws
    def test_multiple_distribution_origin_failover(self):
        cloudfront_client = client("cloudfront", region_name=AWS_REGION_US_EAST_1)

        # Crear una distribución de CloudFront simulada
        distribution_config = {
            "CallerReference": "test-distribution",
            "Comment": "test distribution",
            "Enabled": True,
            "Origins": {
                "Quantity": 2,
                "Items": [
                    {
                        "Id": "1",
                        "DomainName": "example.com",
                    },
                    {
                        "Id": "2",
                        "DomainName": "example2.com",
                    },
                    {
                        "Id": "3",
                        "DomainName": "example3.com",
                    },
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "1",
                "ViewerProtocolPolicy": "allow-all",
            },
        }

        response = cloudfront_client.create_distribution(
            DistributionConfig=distribution_config
        )
        distribution_id = response["Distribution"]["Id"]
        distribution_arn = response["Distribution"]["ARN"]

        from prowler.providers.aws.services.cloudfront.cloudfront_service import (
            CloudFront,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudfront.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_client",
                new=CloudFront(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudfront.cloudfront_distributions_multiple_origin_failover_configured.cloudfront_distributions_multiple_origin_failover_configured import (
                    cloudfront_distributions_multiple_origin_failover_configured,
                )

                check = cloudfront_distributions_multiple_origin_failover_configured()
                result = check.execute()

                assert len(result) == 1
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_arn == distribution_arn
                assert result[0].resource_id == distribution_id
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"CloudFront Distribution {distribution_id} has an origin group with two or more origins."
                )
