from unittest import mock

from prowler.providers.aws.services.opensearch.opensearch_service import (
    OpenSearchDomain,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

domain_name = "test-domain"
domain_arn = f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{domain_name}"

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

policy_data_source_ip_full = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["es:ESHttp*"],
            "Condition": {"IpAddress": {"aws:SourceIp": ["*"]}},
            "Resource": f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{domain_name}/*",
        }
    ],
}

policy_data_source_whole_internet = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["es:ESHttp*"],
            "Condition": {"IpAddress": {"aws:SourceIp": ["0.0.0.0/0"]}},
            "Resource": f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{domain_name}/*",
        }
    ],
}


class Test_opensearch_service_domains_not_publicly_accessible:
    def test_no_domains(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible import (
                opensearch_service_domains_not_publicly_accessible,
            )

            check = opensearch_service_domains_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_policy_data_restricted(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                access_policy=policy_data_restricted,
            )
        )
        opensearch_client.opensearch_domains[0].logging = []

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible import (
                opensearch_service_domains_not_publicly_accessible,
            )

            check = opensearch_service_domains_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} does not allow anonymous access."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn

    def test_policy_data_not_restricted_with_principal_AWS(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                access_policy=policy_data_not_restricted,
            )
        )
        opensearch_client.opensearch_domains[0].logging = []

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible import (
                opensearch_service_domains_not_publicly_accessible,
            )

            check = opensearch_service_domains_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} policy allows access (Principal: '*')."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn

    def test_policy_data_not_restricted_with_principal_no_AWS(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                access_policy=policy_data_not_restricted_principal,
            )
        )
        opensearch_client.opensearch_domains[0].logging = []

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible import (
                opensearch_service_domains_not_publicly_accessible,
            )

            check = opensearch_service_domains_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} policy allows access (Principal: '*')."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn

    def test_policy_data_not_restricted_ip_full(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                access_policy=policy_data_source_ip_full,
            )
        )
        opensearch_client.opensearch_domains[0].logging = []

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible import (
                opensearch_service_domains_not_publicly_accessible,
            )

            check = opensearch_service_domains_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} policy allows access (Principal: '*') and network *."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn

    def test_policy_data_not_restricted_whole_internet(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                access_policy=policy_data_source_whole_internet,
            )
        )
        opensearch_client.opensearch_domains[0].logging = []

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_not_publicly_accessible.opensearch_service_domains_not_publicly_accessible import (
                opensearch_service_domains_not_publicly_accessible,
            )

            check = opensearch_service_domains_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} policy allows access (Principal: '*') and network 0.0.0.0/0."
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
