"""Coverage for ``Scan`` constructor exclusion semantics.

The Scan class is the single execution entry point used by both the CLI
and the API worker. Its exclusion validation must:

- Reject duplicates and unknown identifiers with actionable errors.
- Validate excluded checks against the FULL provider catalog so a global
  configuration can exclude a valid check that is not part of a scoped
  run (see the SDK acceptance criteria for scan-configuration exclusions).
- Refuse a configuration that would leave nothing to execute.
- Produce a deterministic, sorted final scope.

The catalog dependencies (``CheckMetadata.get_bulk``, ``Compliance.get_bulk``,
``list_services``, ``load_checks_to_execute``) are patched so tests stay
focused on the exclusion logic and avoid walking the provider package tree.
"""

from unittest.mock import MagicMock, patch

import pytest

from prowler.lib.scan.exceptions.exceptions import (
    ScanInvalidCheckError,
    ScanInvalidServiceError,
)
from prowler.lib.scan.scan import Scan
from tests.providers.aws.utils import set_mocked_aws_provider

# The provider catalog for these tests: three checks spread across two
# services (``accessanalyzer`` and ``s3``). Keeps assertions readable.
PROVIDER_CATALOG = {
    "accessanalyzer_enabled",
    "s3_bucket_encryption_enabled",
    "s3_bucket_public_access",
}
PROVIDER_SERVICES = ["accessanalyzer", "s3"]


@pytest.fixture
def scan_provider():
    provider = set_mocked_aws_provider()
    metadata = MagicMock()
    metadata.Categories = []
    bulk = {check: metadata for check in PROVIDER_CATALOG}

    with (
        patch(
            "prowler.lib.scan.scan.CheckMetadata.get_bulk",
            return_value=bulk,
        ),
        patch("prowler.lib.scan.scan.Compliance.get_bulk", return_value={}),
        patch(
            "prowler.lib.scan.scan.update_checks_metadata_with_compliance",
            side_effect=lambda _compliance, checks: checks,
        ),
        patch(
            "prowler.lib.scan.scan.load_checks_to_execute",
            side_effect=lambda **kwargs: set(kwargs["check_list"] or PROVIDER_CATALOG),
        ),
        patch(
            "prowler.lib.scan.scan.list_services",
            return_value=PROVIDER_SERVICES,
        ),
    ):
        yield provider


class Test_Exclusion_No_Ops:
    def test_none_lists_are_no_ops(self, scan_provider):
        scan = Scan(scan_provider, excluded_checks=None, excluded_services=None)
        assert scan.checks_to_execute == sorted(PROVIDER_CATALOG)

    def test_empty_lists_are_no_ops(self, scan_provider):
        scan = Scan(scan_provider, excluded_checks=[], excluded_services=[])
        assert scan.checks_to_execute == sorted(PROVIDER_CATALOG)


class Test_Excluded_Checks:
    def test_valid_check_is_removed_from_the_scope(self, scan_provider):
        scan = Scan(
            scan_provider,
            excluded_checks=["s3_bucket_public_access"],
        )
        assert scan.checks_to_execute == sorted(
            PROVIDER_CATALOG - {"s3_bucket_public_access"}
        )

    def test_excluded_check_may_be_outside_the_selected_scope(self, scan_provider):
        # ``s3_bucket_public_access`` is not in the explicitly selected
        # ``checks`` list but is still a valid provider check, so the
        # global exclusion must be accepted and be a no-op for this run.
        scan = Scan(
            scan_provider,
            checks=["accessanalyzer_enabled"],
            excluded_checks=["s3_bucket_public_access"],
        )
        assert scan.checks_to_execute == ["accessanalyzer_enabled"]

    def test_unknown_check_is_rejected(self, scan_provider):
        with pytest.raises(ScanInvalidCheckError):
            Scan(scan_provider, excluded_checks=["not_a_real_check"])

    def test_duplicate_checks_are_rejected(self, scan_provider):
        with pytest.raises(ScanInvalidCheckError):
            Scan(
                scan_provider,
                excluded_checks=[
                    "s3_bucket_public_access",
                    "s3_bucket_public_access",
                ],
            )


class Test_Excluded_Services:
    def test_service_exclusion_removes_every_check_in_the_service(self, scan_provider):
        scan = Scan(scan_provider, excluded_services=["s3"])
        assert scan.checks_to_execute == ["accessanalyzer_enabled"]

    def test_unknown_service_is_rejected(self, scan_provider):
        with pytest.raises(ScanInvalidServiceError):
            Scan(scan_provider, excluded_services=["not_a_real_service"])

    def test_duplicate_services_are_rejected(self, scan_provider):
        with pytest.raises(ScanInvalidServiceError):
            Scan(scan_provider, excluded_services=["s3", "s3"])


class Test_Combined_Exclusions:
    def test_selected_checks_plus_excluded_checks_and_services(self, scan_provider):
        scan = Scan(
            scan_provider,
            checks=["accessanalyzer_enabled", "s3_bucket_encryption_enabled"],
            excluded_checks=["s3_bucket_public_access"],
            excluded_services=["s3"],
        )
        # The explicit ``checks`` selection is narrowed by both the
        # excluded_checks (drops nothing extra here) and excluded_services
        # (drops every s3 check), leaving accessanalyzer alone.
        assert scan.checks_to_execute == ["accessanalyzer_enabled"]

    def test_result_is_sorted_and_deterministic(self, scan_provider):
        scan = Scan(
            scan_provider,
            excluded_checks=["s3_bucket_public_access"],
        )
        assert scan.checks_to_execute == sorted(scan.checks_to_execute)


class Test_Empty_Final_Scope_Is_Rejected:
    def test_excluding_every_service_is_rejected(self, scan_provider):
        with pytest.raises(ScanInvalidCheckError):
            Scan(scan_provider, excluded_services=PROVIDER_SERVICES)

    def test_excluding_every_check_is_rejected(self, scan_provider):
        with pytest.raises(ScanInvalidCheckError):
            Scan(scan_provider, excluded_checks=sorted(PROVIDER_CATALOG))


class Test_Already_Empty_Scope_Does_Not_Blame_Exclusions:
    """When a positive filter (severity, categories, checks that resolve
    to nothing) leaves the scope empty *before* exclusions run, the
    exclusion pass must not falsely claim to be the cause. Otherwise the
    real reason (empty selection) is masked by a misleading error."""

    def test_empty_initial_scope_with_valid_exclusions_does_not_raise(
        self, scan_provider
    ):
        # Force ``load_checks_to_execute`` to return an empty scope while
        # keeping the exclusion inputs valid against the provider catalog.
        with patch(
            "prowler.lib.scan.scan.load_checks_to_execute",
            return_value=set(),
        ):
            scan = Scan(
                scan_provider,
                excluded_checks=["s3_bucket_public_access"],
            )
        assert scan.checks_to_execute == []
