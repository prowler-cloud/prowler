from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

domain_name = "test-domain"


class Test_opensearch_domain_data_nodes_fault_tolerant:
    @mock_aws
    def test_no_domains(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_domain_data_nodes_fault_tolerant.opensearch_domain_data_nodes_fault_tolerant.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_domain_data_nodes_fault_tolerant.opensearch_domain_data_nodes_fault_tolerant import (
                opensearch_domain_data_nodes_fault_tolerant,
            )

            check = opensearch_domain_data_nodes_fault_tolerant()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_domain_with_one_data_node(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_EU_WEST_1)
        domain_arn = opensearch_client.create_domain(
            DomainName=domain_name,
            ClusterConfig={
                "InstanceCount": 1,
                "InstanceType": "m3.medium.search",
                "ZoneAwarenessEnabled": True,
            },
            TagList=[
                {"Key": "test", "Value": "test"},
            ],
        )["DomainStatus"]["ARN"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_domain_data_nodes_fault_tolerant.opensearch_domain_data_nodes_fault_tolerant.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_domain_data_nodes_fault_tolerant.opensearch_domain_data_nodes_fault_tolerant import (
                opensearch_domain_data_nodes_fault_tolerant,
            )

            check = opensearch_domain_data_nodes_fault_tolerant()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} does not have at least 3 data nodes, which is recommended for fault tolerance."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_domain_with_three_data_nodes_and_not_zone_awaraness(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_EU_WEST_1)
        domain_arn = opensearch_client.create_domain(
            DomainName=domain_name,
            ClusterConfig={
                "InstanceCount": 3,
                "InstanceType": "m3.medium.search",
                "ZoneAwarenessEnabled": False,
            },
            TagList=[{"Key": "test", "Value": "test"}],
        )["DomainStatus"]["ARN"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_domain_data_nodes_fault_tolerant.opensearch_domain_data_nodes_fault_tolerant.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_domain_data_nodes_fault_tolerant.opensearch_domain_data_nodes_fault_tolerant import (
                opensearch_domain_data_nodes_fault_tolerant,
            )

            check = opensearch_domain_data_nodes_fault_tolerant()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} does not have zone awareness enabled, which is recommended for fault tolerance."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_domain_with_three_data_nodes_and_zone_awaraness(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_EU_WEST_1)
        domain_arn = opensearch_client.create_domain(
            DomainName=domain_name,
            ClusterConfig={
                "InstanceCount": 3,
                "InstanceType": "m3.medium.search",
                "ZoneAwarenessEnabled": True,
            },
            TagList=[{"Key": "test", "Value": "test"}],
        )["DomainStatus"]["ARN"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_domain_data_nodes_fault_tolerant.opensearch_domain_data_nodes_fault_tolerant.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_domain_data_nodes_fault_tolerant.opensearch_domain_data_nodes_fault_tolerant import (
                opensearch_domain_data_nodes_fault_tolerant,
            )

            check = opensearch_domain_data_nodes_fault_tolerant()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} has 3 data nodes and zone awareness enabled."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]
