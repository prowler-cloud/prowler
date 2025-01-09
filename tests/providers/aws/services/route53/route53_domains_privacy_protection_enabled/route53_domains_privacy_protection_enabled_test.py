from unittest import mock

from prowler.providers.aws.services.route53.route53_service import Domain
from tests.providers.aws.utils import AWS_ACCOUNT_ARN, AWS_REGION_US_EAST_1


class Test_route53_domains_privacy_protection_enabled:
    def test_no_domains(self):
        route53domains = mock.MagicMock
        route53domains.domains = {}

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_service.Route53Domains",
            new=route53domains,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_domains_privacy_protection_enabled.route53_domains_privacy_protection_enabled import (
                route53_domains_privacy_protection_enabled,
            )

            check = route53_domains_privacy_protection_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_domain_privacy_protection_disabled(self):
        route53domains = mock.MagicMock
        route53domains.audited_account_arn = AWS_ACCOUNT_ARN
        domain_name = "test-domain.com"
        route53domains.domains = {
            domain_name: Domain(
                name=domain_name,
                arn=f"arn:aws:route53:::domain/{domain_name}",
                region=AWS_REGION_US_EAST_1,
                admin_privacy=False,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_service.Route53Domains",
            new=route53domains,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_domains_privacy_protection_enabled.route53_domains_privacy_protection_enabled import (
                route53_domains_privacy_protection_enabled,
            )

            check = route53_domains_privacy_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == f"arn:aws:route53:::domain/{domain_name}"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Contact information is public for the {domain_name} domain."
            )

    def test_domain_privacy_protection_enabled(self):
        route53domains = mock.MagicMock
        route53domains.audited_account_arn = AWS_ACCOUNT_ARN
        domain_name = "test-domain.com"
        route53domains.domains = {
            domain_name: Domain(
                name=domain_name,
                arn=f"arn:aws:route53:::domain/{domain_name}",
                region=AWS_REGION_US_EAST_1,
                admin_privacy=True,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_service.Route53Domains",
            new=route53domains,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_domains_privacy_protection_enabled.route53_domains_privacy_protection_enabled import (
                route53_domains_privacy_protection_enabled,
            )

            check = route53_domains_privacy_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == domain_name
            assert result[0].resource_arn == f"arn:aws:route53:::domain/{domain_name}"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Contact information is private for the {domain_name} domain."
            )
