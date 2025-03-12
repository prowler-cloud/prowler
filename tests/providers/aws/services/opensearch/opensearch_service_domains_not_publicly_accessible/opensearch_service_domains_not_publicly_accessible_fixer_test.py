from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_WEST_2,
    set_mocked_aws_provider,
)

domain_name = "test-domain"

policy_data_restricted = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": [f"{AWS_ACCOUNT_NUMBER}"]},
            "Action": ["es:*"],
            "Resource": f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{domain_name}/*",
        }
    ],
}

policy_data_not_restricted = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["es:*"],
            "Resource": f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{domain_name}/*",
        }
    ],
}

policy_data_not_restricted_principal = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["es:*"],
            "Resource": f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{domain_name}/*",
        }
    ],
}


class Test_opensearch_service_domains_not_publicly_accessible_fixer:
    @mock_aws
    def test_policy_data_restricted_error(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_WEST_2)
        opensearch_client.create_domain(DomainName=domain_name)["DomainStatus"]["ARN"]
        opensearch_client.update_domain_config(
            DomainName=domain_name,
            AccessPolicies=str(policy_data_restricted),
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_WEST_2])

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible_fixer.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible_fixer import (
                fixer,
            )

            assert not fixer("domain_name_non_existing", AWS_REGION_US_WEST_2)

    @mock_aws
    def test_policy_data_not_restricted_with_principal_AWS(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_WEST_2)
        opensearch_client.create_domain(DomainName=domain_name)["DomainStatus"]["ARN"]
        opensearch_client.update_domain_config(
            DomainName=domain_name,
            AccessPolicies=dumps(policy_data_not_restricted),
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_WEST_2])

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible_fixer.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible_fixer import (
                fixer,
            )

            assert fixer(domain_name, AWS_REGION_US_WEST_2)

    @mock_aws
    def test_policy_data_not_restricted_with_principal_no_AWS(self):
        opensearch_client = client("opensearch", region_name=AWS_REGION_US_WEST_2)
        opensearch_client.create_domain(DomainName=domain_name)["DomainStatus"]["ARN"]
        opensearch_client.update_domain_config(
            DomainName=domain_name,
            AccessPolicies=dumps(policy_data_not_restricted_principal),
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_WEST_2])

        from prowler.providers.aws.services.opensearch.opensearch_service import (
            OpenSearchService,
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible_fixer.opensearch_client",
            new=OpenSearchService(aws_provider),
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible_fixer import (
                fixer,
            )

            assert fixer(domain_name, AWS_REGION_US_WEST_2)
