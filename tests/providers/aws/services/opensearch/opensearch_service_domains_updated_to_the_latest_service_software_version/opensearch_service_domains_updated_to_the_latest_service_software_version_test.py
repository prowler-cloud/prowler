from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListDomainNames":
        return {
            "DomainNames": [
                {
                    "DomainName": "test-domain-updates",
                },
            ]
        }
    if operation_name == "DescribeDomain":
        return {
            "DomainStatus": {
                "DomainName": "test-domain-updates",
                "EngineVersion": "OpenSearch2.0",
                "ServiceSoftwareOptions": {
                    "UpdateAvailable": True,
                },
                "ARN": f"arn:aws:es:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/test-domain-updates",
                "ClusterConfig": {
                    "InstanceCount": 1,
                },
                "AdvancedSecurityOptions": {
                    "InternalUserDatabaseEnabled": False,
                },
                "CognitoOptions": {
                    "Enabled": False,
                },
                "EncryptionAtRestOptions": {
                    "Enabled": False,
                },
                "NodeToNodeEncryptionOptions": {
                    "Enabled": False,
                },
                "DomainEndpointOptions": {
                    "EnforceHTTPS": False,
                },
            }
        }
    return make_api_call(self, operation_name, kwarg)


class Test_opensearch_service_domains_updated_to_the_latest_service_software_version:
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
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_updated_to_the_latest_service_software_version.opensearch_service_domains_updated_to_the_latest_service_software_version.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_updated_to_the_latest_service_software_version.opensearch_service_domains_updated_to_the_latest_service_software_version import (
                opensearch_service_domains_updated_to_the_latest_service_software_version,
            )

            check = (
                opensearch_service_domains_updated_to_the_latest_service_software_version()
            )
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_updates_available(self):
        client("opensearch", region_name=AWS_REGION_US_EAST_1)
        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_updated_to_the_latest_service_software_version.opensearch_service_domains_updated_to_the_latest_service_software_version.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_updated_to_the_latest_service_software_version.opensearch_service_domains_updated_to_the_latest_service_software_version import (
                opensearch_service_domains_updated_to_the_latest_service_software_version,
            )

            check = (
                opensearch_service_domains_updated_to_the_latest_service_software_version()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Opensearch domain test-domain-updates with version OpenSearch2.0 has internal updates available."
            )
            assert result[0].resource_id == "test-domain-updates"
            assert (
                result[0].resource_arn
                == f"arn:aws:es:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/test-domain-updates"
            )

    @mock_aws
    def test_no_updates_availables(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_EAST_1)
        domain = opensearch_client.create_domain(
            DomainName="test-domain-no-updates",
            SoftwareUpdateOptions={"AutoSoftwareUpdateEnabled": True},
        )
        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_updated_to_the_latest_service_software_version.opensearch_service_domains_updated_to_the_latest_service_software_version.opensearch_client",
            new=OpenSearchService(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_updated_to_the_latest_service_software_version.opensearch_service_domains_updated_to_the_latest_service_software_version import (
                opensearch_service_domains_updated_to_the_latest_service_software_version,
            )

            check = (
                opensearch_service_domains_updated_to_the_latest_service_software_version()
            )
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Opensearch domain test-domain-no-updates with version {domain['DomainStatus']['EngineVersion']} does not have internal updates available."
            )
            assert result[0].resource_id == domain["DomainStatus"]["DomainName"]
            assert (
                result[0].resource_arn
                == f"arn:aws:es:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:domain/{domain['DomainStatus']['DomainName']}"
            )
