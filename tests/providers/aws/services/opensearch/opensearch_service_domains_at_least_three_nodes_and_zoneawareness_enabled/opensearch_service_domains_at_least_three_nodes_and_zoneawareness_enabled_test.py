from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled:
    @mock_aws
    def test_no_domains(self):
        client("opensearch", region_name=AWS_REGION_US_EAST_1)

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled import (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled,
            )

            check = (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled()
            )
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_instance_count_less_than_three_zoneawareness_enabled(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_EAST_1)
        domain = opensearch_client.create_domain(
            DomainName="test-domain",
            ClusterConfig={"ZoneAwarenessEnabled": True, "InstanceCount": 2},
        )

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled import (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled,
            )

            check = (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Opensearch domain test-domain has zone awareness enabled, but only 2 data nodes."
            )
            assert result[0].resource_id == domain["DomainStatus"]["DomainName"]
            assert (
                result[0].resource_arn
                == f"arn:aws:es:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/{domain["DomainStatus"]["DomainName"]}"
            )

    @mock_aws
    def test_instance_count_more_than_three_zoneawareness_not_enabled(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_EAST_1)
        domain = opensearch_client.create_domain(
            DomainName="test-domain",
            ClusterConfig={"ZoneAwarenessEnabled": False, "InstanceCount": 3},
        )

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled import (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled,
            )

            check = (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Opensearch domain test-domain has 3 data nodes, but zone awareness is not enabled."
            )
            assert result[0].resource_id == domain["DomainStatus"]["DomainName"]
            assert (
                result[0].resource_arn
                == f"arn:aws:es:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/{domain["DomainStatus"]["DomainName"]}"
            )

    @mock_aws
    def test_instance_count_less_than_three_zoneawareness_not_enabled(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_EAST_1)
        domain = opensearch_client.create_domain(
            DomainName="test-domain",
            ClusterConfig={"ZoneAwarenessEnabled": False, "InstanceCount": 2},
        )

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled import (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled,
            )

            check = (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Opensearch domain test-domain does not meet the requirements: it has less than 3 data nodes and zone awareness is not enabled."
            )
            assert result[0].resource_id == domain["DomainStatus"]["DomainName"]
            assert (
                result[0].resource_arn
                == f"arn:aws:es:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/{domain["DomainStatus"]["DomainName"]}"
            )

    @mock_aws
    def test_logging_instance_count_more_than_three_zoneawareness_enabled(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_EAST_1)
        domain = opensearch_client.create_domain(
            DomainName="test-domain",
            ClusterConfig={"ZoneAwarenessEnabled": True, "InstanceCount": 3},
        )

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled.opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled import (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled,
            )

            check = (
                opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Opensearch domain test-domain has 3 data nodes and zone awareness enabled."
            )
            assert result[0].resource_id == domain["DomainStatus"]["DomainName"]
            assert (
                result[0].resource_arn
                == f"arn:aws:es:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/{domain["DomainStatus"]["DomainName"]}"
            )
