from unittest import mock

from prowler.providers.aws.services.opensearch.opensearch_service import (
    OpenSearchDomain,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

domain_name = "test-domain"
domain_arn = f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{domain_name}"


class Test_opensearch_service_domains_use_cognito_authentication_for_kibana:
    def test_no_domains(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_use_cognito_authentication_for_kibana.opensearch_service_domains_use_cognito_authentication_for_kibana import (
                opensearch_service_domains_use_cognito_authentication_for_kibana,
            )

            check = opensearch_service_domains_use_cognito_authentication_for_kibana()
            result = check.execute()
            assert len(result) == 0

    def test_neither_cognito_nor_saml_enabled(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                cognito_options=False,
                saml_enabled=False,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_use_cognito_authentication_for_kibana.opensearch_service_domains_use_cognito_authentication_for_kibana import (
                opensearch_service_domains_use_cognito_authentication_for_kibana,
            )

            check = opensearch_service_domains_use_cognito_authentication_for_kibana()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} has neither Amazon Cognito nor SAML authentication for Kibana enabled."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].resource_tags == []

    def test_cognito_enabled(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                cognito_options=True,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_use_cognito_authentication_for_kibana.opensearch_service_domains_use_cognito_authentication_for_kibana import (
                opensearch_service_domains_use_cognito_authentication_for_kibana,
            )

            check = opensearch_service_domains_use_cognito_authentication_for_kibana()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} has either Amazon Cognito or SAML authentication for Kibana enabled."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].resource_tags == []
            assert result[0].resource_arn == domain_arn

    def test_saml_enabled(self):
        opensearch_client = mock.MagicMock
        opensearch_client.opensearch_domains = []
        opensearch_client.opensearch_domains.append(
            OpenSearchDomain(
                name=domain_name,
                region=AWS_REGION_EU_WEST_1,
                arn=domain_arn,
                saml_enabled=True,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.opensearch.opensearch_service.OpenSearchService",
            opensearch_client,
        ):
            from prowler.providers.aws.services.opensearch.opensearch_service_domains_use_cognito_authentication_for_kibana.opensearch_service_domains_use_cognito_authentication_for_kibana import (
                opensearch_service_domains_use_cognito_authentication_for_kibana,
            )

            check = opensearch_service_domains_use_cognito_authentication_for_kibana()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Opensearch domain {domain_name} has either Amazon Cognito or SAML authentication for Kibana enabled."
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == domain_arn
            assert result[0].resource_tags == []
            assert result[0].resource_arn == domain_arn
