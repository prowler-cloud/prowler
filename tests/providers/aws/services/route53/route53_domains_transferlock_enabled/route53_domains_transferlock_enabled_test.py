from unittest import mock

from prowler.providers.aws.services.route53.route53_service import Domain

AWS_REGION = "us-east-1"


class Test_route53_domains_transferlock_enabled:
    def test_no_domains(self):
        route53domains = mock.MagicMock
        route53domains.domains = {}

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_service.Route53Domains",
            new=route53domains,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_domains_transferlock_enabled.route53_domains_transferlock_enabled import (
                route53_domains_transferlock_enabled,
            )

            check = route53_domains_transferlock_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_domain_transfer_lock_disabled(self):
        route53domains = mock.MagicMock
        domain_name = "test-domain.com"
        route53domains.domains = {
            domain_name: Domain(
                name=domain_name,
                region=AWS_REGION,
                admin_privacy=False,
                status_list=[""],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_service.Route53Domains",
            new=route53domains,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_domains_transferlock_enabled.route53_domains_transferlock_enabled import (
                route53_domains_transferlock_enabled,
            )

            check = route53_domains_transferlock_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == domain_name
            assert result[0].region == AWS_REGION
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Transfer Lock is disabled for the {domain_name} domain."
            )

    def test_domain_transfer_lock_enabled(self):
        route53domains = mock.MagicMock
        domain_name = "test-domain.com"
        route53domains.domains = {
            domain_name: Domain(
                name=domain_name,
                region=AWS_REGION,
                admin_privacy=False,
                status_list=["clientTransferProhibited"],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.route53.route53_service.Route53Domains",
            new=route53domains,
        ):
            # Test Check
            from prowler.providers.aws.services.route53.route53_domains_transferlock_enabled.route53_domains_transferlock_enabled import (
                route53_domains_transferlock_enabled,
            )

            check = route53_domains_transferlock_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == domain_name
            assert result[0].region == AWS_REGION
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Transfer Lock is enabled for the {domain_name} domain."
            )
