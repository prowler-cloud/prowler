from re import search
from unittest import mock

from prowler.providers.aws.services.opensearch.opensearch_service import (
    OpenSearchDomain,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

domain_name = "test-domain"
domain_arn = f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{domain_name}"


class Test_opensearch_service_domains_https_communications_enforced:
    def test_no_domains(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_https_communications_enforced.opensearch_service_domains_https_communications_enforced import (
                opensearch_service_domains_https_communications_enforced,
            )

            check = opensearch_service_domains_https_communications_enforced()
            result = check.execute()
            assert len(result) == 0

    def test_no_https_enabled(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name, region=AWS_REGION, arn=domain_arn, enforce_https=False
            )
        )
        opensearch_client.opensearch_domains[0].logging = []

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_https_communications_enforced.opensearch_service_domains_https_communications_enforced import (
                opensearch_service_domains_https_communications_enforced,
            )

            check = opensearch_service_domains_https_communications_enforced()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have enforce HTTPS enabled", result[0].status_extended
            )
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn

    def test_https_enabled(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name, region=AWS_REGION, arn=domain_arn, enforce_https=True
            )
        )
        opensearch_client.opensearch_domains[0].logging = []

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_https_communications_enforced.opensearch_service_domains_https_communications_enforced import (
                opensearch_service_domains_https_communications_enforced,
            )

            check = opensearch_service_domains_https_communications_enforced()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("has enforce HTTPS enabled", result[0].status_extended)
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
