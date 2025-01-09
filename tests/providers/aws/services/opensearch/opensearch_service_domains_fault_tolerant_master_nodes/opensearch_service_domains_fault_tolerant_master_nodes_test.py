from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

domain_name = "test-domain"


class Test_opensearch_service_domains_fault_tolerant_master_nodes:
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
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_service_domains_fault_tolerant_master_nodes import (
                opensearch_service_domains_fault_tolerant_master_nodes,
            )

            check = opensearch_service_domains_fault_tolerant_master_nodes()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_domain_no_master_nodes_enabled(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_EU_WEST_1)
        opensearch_client.create_domain(
            DomainName=domain_name,
            ClusterConfig={
                "DedicatedMasterEnabled": False,
            },
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_service_domains_fault_tolerant_master_nodes import (
                opensearch_service_domains_fault_tolerant_master_nodes,
            )

            check = opensearch_service_domains_fault_tolerant_master_nodes()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} has dedicated master nodes disabled."
            )
            assert result[0].resource_id == domain_name
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_domain_with_one_master_node(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_EU_WEST_1)
        domain_arn = opensearch_client.create_domain(
            DomainName=domain_name,
            ClusterConfig={
                "DedicatedMasterEnabled": True,
                "DedicatedMasterCount": 1,
                "DedicatedMasterType": "m3.medium.search",
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
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_service_domains_fault_tolerant_master_nodes import (
                opensearch_service_domains_fault_tolerant_master_nodes,
            )

            check = opensearch_service_domains_fault_tolerant_master_nodes()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} does not have at least 3 dedicated master nodes."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_domain_with_three_master_nodes(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_EU_WEST_1)
        domain_arn = opensearch_client.create_domain(
            DomainName=domain_name,
            ClusterConfig={
                "DedicatedMasterEnabled": True,
                "DedicatedMasterCount": 3,
                "DedicatedMasterType": "m3.medium.search",
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
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_fault_tolerant_master_nodes.opensearch_service_domains_fault_tolerant_master_nodes import (
                opensearch_service_domains_fault_tolerant_master_nodes,
            )

            check = opensearch_service_domains_fault_tolerant_master_nodes()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} has 3 dedicated master nodes, which guarantees fault tolerance on the master nodes."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]
