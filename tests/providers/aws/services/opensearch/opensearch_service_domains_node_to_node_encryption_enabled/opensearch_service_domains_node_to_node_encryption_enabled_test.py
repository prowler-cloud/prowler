from re import search
from unittest import mock

from prowler.providers.aws.services.opensearch.opensearch_service import (
    OpenSearchDomain,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

domain_name = "test-domain"
domain_arn = f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{domain_name}"


class Test_opensearch_service_domains_node_to_node_encryption_enabled:
    def test_no_domains(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_service_domains_node_to_node_encryption_enabled import (
                opensearch_service_domains_node_to_node_encryption_enabled,
            )

            check = opensearch_service_domains_node_to_node_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_encryption_enabled(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                node_to_node_encryption=False,
            )
        )
        opensearch_client.opensearch_domains[0].logging = []

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_service_domains_node_to_node_encryption_enabled import (
                opensearch_service_domains_node_to_node_encryption_enabled,
            )

            check = opensearch_service_domains_node_to_node_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have node-to-node encryption enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn

    def test_encryption_enabled(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                node_to_node_encryption=True,
            )
        )
        opensearch_client.opensearch_domains[0].logging = []

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_service_domains_node_to_node_encryption_enabled import (
                opensearch_service_domains_node_to_node_encryption_enabled,
            )

            check = opensearch_service_domains_node_to_node_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has node-to-node encryption enabled", result[0].status_extended
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
