from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.trustedadvisor.trustedadvisor_service import Check

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

detector_id = str(uuid4())


class Test_trustedadvisor_errors_and_warnings:
    def test_no_detectors(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.enabled = False
        trustedadvisor_client.account = AWS_ACCOUNT_NUMBER
        trustedadvisor_client.region = AWS_REGION
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_errors_and_warnings.trustedadvisor_errors_and_warnings import (
                trustedadvisor_errors_and_warnings,
            )

            check = trustedadvisor_errors_and_warnings()
            result = check.execute()
            assert len(result) == 1
            assert (
                result[0].status_extended
                == "Amazon Web Services Premium Support Subscription is required to use this service."
            )

    def test_trustedadvisor_all_passed_checks(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.enabled = True
        trustedadvisor_client.checks.append(
            Check(
                id="check1",
                name="check1",
                region=AWS_REGION,
                status="ok",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_errors_and_warnings.trustedadvisor_errors_and_warnings import (
                trustedadvisor_errors_and_warnings,
            )

            check = trustedadvisor_errors_and_warnings()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("ok", result[0].status_extended)
            assert result[0].resource_id == "check1"

    def test_trustedadvisor_error_check(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.enabled = True
        trustedadvisor_client.checks.append(
            Check(
                id="check1",
                name="check1",
                region=AWS_REGION,
                status="error",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_errors_and_warnings.trustedadvisor_errors_and_warnings import (
                trustedadvisor_errors_and_warnings,
            )

            check = trustedadvisor_errors_and_warnings()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("error", result[0].status_extended)
            assert result[0].resource_id == "check1"

    def test_trustedadvisor_not_available_check(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.enabled = True
        trustedadvisor_client.checks.append(
            Check(
                id="check1",
                name="check1",
                region=AWS_REGION,
                status="not_available",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_errors_and_warnings.trustedadvisor_errors_and_warnings import (
                trustedadvisor_errors_and_warnings,
            )

            check = trustedadvisor_errors_and_warnings()
            result = check.execute()
            assert len(result) == 0
