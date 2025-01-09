from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_opensearch_service_domains_node_to_node_encryption_enabled:
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
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_service_domains_node_to_node_encryption_enabled import (
                opensearch_service_domains_node_to_node_encryption_enabled,
            )

            check = opensearch_service_domains_node_to_node_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_no_encryption_enabled(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_EAST_1)
        domain = opensearch_client.create_domain(
            DomainName="test-domain-no-encryption",
            NodeToNodeEncryptionOptions={"Enabled": False},
        )
        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_service_domains_node_to_node_encryption_enabled import (
                opensearch_service_domains_node_to_node_encryption_enabled,
            )

            check = opensearch_service_domains_node_to_node_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Opensearch domain test-domain-no-encryption does not have node-to-node encryption enabled."
            )
            assert result[0].resource_id == domain["DomainStatus"]["DomainName"]
            assert (
                result[0].resource_arn
                == f"arn:aws:es:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/{domain['DomainStatus']['DomainName']}"
            )

    @mock_aws
    def test_encryption_enabled(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_EAST_1)
        domain = opensearch_client.create_domain(
            DomainName="test-domain-encryption",
            NodeToNodeEncryptionOptions={"Enabled": True},
        )
        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_node_to_node_encryption_enabled.opensearch_service_domains_node_to_node_encryption_enabled import (
                opensearch_service_domains_node_to_node_encryption_enabled,
            )

            check = opensearch_service_domains_node_to_node_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Opensearch domain test-domain-encryption has node-to-node encryption enabled."
            )
            assert result[0].resource_id == domain["DomainStatus"]["DomainName"]
            assert (
                result[0].resource_arn
                == f"arn:aws:es:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/{domain['DomainStatus']['DomainName']}"
            )
