import os
import time
import uuid
from unittest.mock import Mock, patch

import matplotlib
import pytest
from reportlab.lib import colors
from tasks.jobs.report import (
    STALE_TMP_OUTPUT_MAX_AGE_HOURS,
    STALE_TMP_OUTPUT_LOCK_FILE_NAME,
    _cleanup_stale_tmp_output_directories,
    _is_scan_directory_protected,
    _pick_latest_cis_variant,
    _should_run_stale_cleanup,
    generate_compliance_reports,
    generate_threatscore_report,
)
from tasks.jobs.reports import (
    CHART_COLOR_GREEN_1,
    CHART_COLOR_GREEN_2,
    CHART_COLOR_ORANGE,
    CHART_COLOR_RED,
    CHART_COLOR_YELLOW,
    COLOR_BLUE,
    COLOR_ENS_ALTO,
    COLOR_HIGH_RISK,
    COLOR_LOW_RISK,
    COLOR_MEDIUM_RISK,
    COLOR_NIS2_PRIMARY,
    COLOR_SAFE,
    create_pdf_styles,
    get_chart_color_for_percentage,
    get_color_for_compliance,
    get_color_for_risk_level,
    get_color_for_weight,
)
from tasks.jobs.threatscore_utils import (
    _aggregate_requirement_statistics_from_database,
    _load_findings_for_requirement_checks,
)

from api.models import (
    Finding,
    Resource,
    ResourceFindingMapping,
    ResourceTag,
    ResourceTagMapping,
    StateChoices,
    StatusChoices,
)
from prowler.lib.check.models import Severity

matplotlib.use("Agg")  # Use non-interactive backend for tests


@pytest.mark.django_db
class TestAggregateRequirementStatistics:
    """Test suite for _aggregate_requirement_statistics_from_database function."""

    def _create_finding_with_resource(
        self, tenant, scan, uid, check_id, status, severity=Severity.high
    ):
        """Helper to create a finding linked to a resource (matching scan processing behavior)."""
        finding = Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid=uid,
            check_id=check_id,
            status=status,
            severity=severity,
            impact=severity,
            check_metadata={},
            raw_result={},
        )
        resource = Resource.objects.create(
            tenant_id=tenant.id,
            provider=scan.provider,
            uid=f"resource-{uid}",
            name=f"resource-{uid}",
            region="us-east-1",
            service="test",
            type="test::resource",
        )
        ResourceFindingMapping.objects.create(
            tenant_id=tenant.id,
            finding=finding,
            resource=resource,
        )
        return finding

    def test_aggregates_findings_correctly(self, tenants_fixture, scans_fixture):
        """Verify correct pass/total counts per check are aggregated from database."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        self._create_finding_with_resource(
            tenant, scan, "finding-1", "check_1", StatusChoices.PASS
        )
        self._create_finding_with_resource(
            tenant, scan, "finding-2", "check_1", StatusChoices.FAIL
        )
        self._create_finding_with_resource(
            tenant, scan, "finding-3", "check_2", StatusChoices.PASS, Severity.medium
        )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert "check_1" in result
        assert result["check_1"]["passed"] == 1
        assert result["check_1"]["total"] == 2

        assert "check_2" in result
        assert result["check_2"]["passed"] == 1
        assert result["check_2"]["total"] == 1

    def test_handles_empty_scan(self, tenants_fixture, scans_fixture):
        """Verify empty result is returned for scan with no findings."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result == {}

    def test_only_failed_findings(self, tenants_fixture, scans_fixture):
        """Verify correct counts when all findings are FAIL."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        self._create_finding_with_resource(
            tenant, scan, "finding-1", "check_1", StatusChoices.FAIL
        )
        self._create_finding_with_resource(
            tenant, scan, "finding-2", "check_1", StatusChoices.FAIL
        )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result["check_1"]["passed"] == 0
        assert result["check_1"]["total"] == 2

    def test_multiple_findings_same_check(self, tenants_fixture, scans_fixture):
        """Verify multiple findings for same check are correctly aggregated."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        for i in range(5):
            self._create_finding_with_resource(
                tenant,
                scan,
                f"finding-{i}",
                "check_1",
                StatusChoices.PASS if i % 2 == 0 else StatusChoices.FAIL,
            )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result["check_1"]["passed"] == 3
        assert result["check_1"]["total"] == 5

    def test_mixed_statuses(self, tenants_fixture, scans_fixture):
        """Verify MANUAL status is not counted in total or passed."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        self._create_finding_with_resource(
            tenant, scan, "finding-1", "check_1", StatusChoices.PASS
        )
        self._create_finding_with_resource(
            tenant, scan, "finding-2", "check_1", StatusChoices.MANUAL
        )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        # MANUAL findings are excluded from the aggregation query
        # since it only counts PASS and FAIL statuses
        assert result["check_1"]["passed"] == 1
        assert result["check_1"]["total"] == 1

    def test_skips_aggregation_for_deleted_provider(
        self, tenants_fixture, scans_fixture
    ):
        """Verify aggregation returns empty when the scan's provider is soft-deleted."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        self._create_finding_with_resource(
            tenant, scan, "finding-1", "check_1", StatusChoices.PASS
        )

        # Soft-delete the provider
        provider = scan.provider
        provider.is_deleted = True
        provider.save(update_fields=["is_deleted"])

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result == {}

    def test_multiple_resources_no_double_count(self, tenants_fixture, scans_fixture):
        """Verify a finding with multiple resources is only counted once."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        finding = Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-1",
            check_id="check_1",
            status=StatusChoices.PASS,
            severity=Severity.high,
            impact=Severity.high,
            check_metadata={},
            raw_result={},
        )
        # Link two resources to the same finding
        for i in range(2):
            resource = Resource.objects.create(
                tenant_id=tenant.id,
                provider=scan.provider,
                uid=f"resource-{i}",
                name=f"resource-{i}",
                region="us-east-1",
                service="test",
                type="test::resource",
            )
            ResourceFindingMapping.objects.create(
                tenant_id=tenant.id,
                finding=finding,
                resource=resource,
            )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result["check_1"]["passed"] == 1
        assert result["check_1"]["total"] == 1


class TestColorHelperFunctions:
    """Test suite for color helper functions."""

    def test_get_color_for_risk_level_high(self):
        """Test high risk level returns correct color."""
        result = get_color_for_risk_level(5)
        assert result == COLOR_HIGH_RISK

    def test_get_color_for_risk_level_medium_high(self):
        """Test risk level 4 returns high risk color."""
        result = get_color_for_risk_level(4)
        assert result == COLOR_HIGH_RISK  # >= 4 is high risk

    def test_get_color_for_risk_level_medium(self):
        """Test risk level 3 returns medium risk color."""
        result = get_color_for_risk_level(3)
        assert result == COLOR_MEDIUM_RISK  # >= 3 is medium risk

    def test_get_color_for_risk_level_low(self):
        """Test low risk level returns safe color."""
        result = get_color_for_risk_level(1)
        assert result == COLOR_SAFE  # < 2 is safe

    def test_get_color_for_weight_high(self):
        """Test high weight returns correct color."""
        result = get_color_for_weight(150)
        assert result == COLOR_HIGH_RISK  # > 100 is high risk

    def test_get_color_for_weight_medium(self):
        """Test medium weight returns low risk color."""
        result = get_color_for_weight(100)
        assert result == COLOR_LOW_RISK  # 51-100 is low risk

    def test_get_color_for_weight_low(self):
        """Test low weight returns safe color."""
        result = get_color_for_weight(50)
        assert result == COLOR_SAFE  # <= 50 is safe

    def test_get_color_for_compliance_high(self):
        """Test high compliance returns green color."""
        result = get_color_for_compliance(85)
        assert result == COLOR_SAFE

    def test_get_color_for_compliance_medium(self):
        """Test medium compliance returns yellow color."""
        result = get_color_for_compliance(70)
        assert result == COLOR_LOW_RISK

    def test_get_color_for_compliance_low(self):
        """Test low compliance returns red color."""
        result = get_color_for_compliance(50)
        assert result == COLOR_HIGH_RISK

    def test_get_chart_color_for_percentage_excellent(self):
        """Test excellent percentage returns correct chart color."""
        result = get_chart_color_for_percentage(90)
        assert result == CHART_COLOR_GREEN_1

    def test_get_chart_color_for_percentage_good(self):
        """Test good percentage returns correct chart color."""
        result = get_chart_color_for_percentage(70)
        assert result == CHART_COLOR_GREEN_2

    def test_get_chart_color_for_percentage_fair(self):
        """Test fair percentage returns correct chart color."""
        result = get_chart_color_for_percentage(50)
        assert result == CHART_COLOR_YELLOW

    def test_get_chart_color_for_percentage_poor(self):
        """Test poor percentage returns correct chart color."""
        result = get_chart_color_for_percentage(30)
        assert result == CHART_COLOR_ORANGE

    def test_get_chart_color_for_percentage_critical(self):
        """Test critical percentage returns correct chart color."""
        result = get_chart_color_for_percentage(10)
        assert result == CHART_COLOR_RED


class TestPDFStylesCreation:
    """Test suite for PDF styles creation."""

    def test_create_pdf_styles_returns_dict(self):
        """Test that create_pdf_styles returns a dictionary."""
        result = create_pdf_styles()
        assert isinstance(result, dict)

    def test_create_pdf_styles_caches_result(self):
        """Test that create_pdf_styles caches the result."""
        result1 = create_pdf_styles()
        result2 = create_pdf_styles()
        assert result1 is result2

    def test_pdf_styles_have_correct_keys(self):
        """Test that PDF styles dictionary has expected keys."""
        result = create_pdf_styles()
        expected_keys = ["title", "h1", "h2", "h3", "normal", "normal_center"]
        for key in expected_keys:
            assert key in result


@pytest.mark.django_db
class TestLoadFindingsForChecks:
    """Test suite for _load_findings_for_requirement_checks function."""

    def test_empty_check_ids_returns_empty(self, tenants_fixture, providers_fixture):
        """Test that empty check_ids list returns empty dict."""
        tenant = tenants_fixture[0]

        mock_prowler_provider = Mock()
        mock_prowler_provider.identity.account = "test-account"

        result = _load_findings_for_requirement_checks(
            str(tenant.id), str(uuid.uuid4()), [], mock_prowler_provider
        )

        assert result == {}

    def test_prefetch_avoids_n_plus_one(self, tenants_fixture, scans_fixture):
        """Loading N findings must NOT execute O(N) extra queries for resources/tags.

        Regression test for PROWLER-1733. ``FindingOutput.transform_api_finding``
        reads ``finding.resources.first()`` and ``resource.tags.all()`` per
        finding. Without ``prefetch_related`` that's 2N additional queries;
        with prefetch it collapses to a small constant per iterator chunk.
        """
        from django.test.utils import CaptureQueriesContext
        from django.db import connections

        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        # Build N findings, each linked to one resource that owns 2 tags.
        N = 20
        for i in range(N):
            finding = Finding.objects.create(
                tenant_id=tenant.id,
                scan=scan,
                uid=f"f-prefetch-{i}",
                check_id="aws_check_prefetch",
                status=StatusChoices.FAIL,
                severity=Severity.high,
                impact=Severity.high,
                check_metadata={
                    "provider": "aws",
                    "checkid": "aws_check_prefetch",
                    "checktitle": "t",
                    "checktype": [],
                    "servicename": "s",
                    "subservicename": "",
                    "severity": "high",
                    "resourcetype": "r",
                    "description": "",
                    "risk": "",
                    "relatedurl": "",
                    "remediation": {
                        "recommendation": {"text": "", "url": ""},
                        "code": {
                            "nativeiac": "",
                            "terraform": "",
                            "cli": "",
                            "other": "",
                        },
                    },
                    "resourceidtemplate": "",
                    "categories": [],
                    "dependson": [],
                    "relatedto": [],
                    "notes": "",
                },
                raw_result={},
            )
            resource = Resource.objects.create(
                tenant_id=tenant.id,
                provider=scan.provider,
                uid=f"r-prefetch-{i}",
                name=f"r-prefetch-{i}",
                metadata="{}",
                details="",
                region="us-east-1",
                service="s",
                type="t::r",
            )
            ResourceFindingMapping.objects.create(
                tenant_id=tenant.id, finding=finding, resource=resource
            )
            for k in ("env", "owner"):
                tag, _ = ResourceTag.objects.get_or_create(
                    tenant_id=tenant.id, key=k, value=f"v-{i}-{k}"
                )
                ResourceTagMapping.objects.create(
                    tenant_id=tenant.id, resource=resource, tag=tag
                )

        mock_provider = Mock()
        mock_provider.type = "aws"
        mock_provider.identity.account = "test"

        # Patch transform_api_finding to a no-op so the test isolates queries
        # to the queryset/prefetch path (transform itself is exercised by
        # the integration tests above and not by this regression check).
        with patch(
            "tasks.jobs.threatscore_utils.FindingOutput.transform_api_finding",
            side_effect=lambda model, provider: Mock(check_id=model.check_id),
        ):
            with CaptureQueriesContext(
                connections["default_read_replica"]
                if "default_read_replica" in connections.databases
                else connections["default"]
            ) as ctx:
                _load_findings_for_requirement_checks(
                    str(tenant.id),
                    str(scan.id),
                    ["aws_check_prefetch"],
                    mock_provider,
                )

        # Expected: a small constant number of queries irrespective of N.
        # Pre-fix this would be ~1 + 2*N. We give some slack for RLS SET
        # LOCAL statements that the rls_transaction emits.
        assert len(ctx.captured_queries) < N, (
            f"Expected O(1) queries with prefetch_related; got "
            f"{len(ctx.captured_queries)} for N={N} (N+1 regression?)"
        )

    def test_max_findings_per_check_cap(self, tenants_fixture, scans_fixture):
        """When a check exceeds ``MAX_FINDINGS_PER_CHECK``, only ``cap`` rows
        are loaded AND ``total_counts_out`` reports the pre-cap total.

        Guards the PROWLER-1733 truncation knob: prevents both runaway memory
        and silent data loss in the PDF (the banner relies on knowing the
        real total).
        """
        from unittest.mock import patch as _patch

        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        # Create 12 findings for a single check; cap to 5.
        check_id = "aws_check_cap_test"
        for i in range(12):
            finding = Finding.objects.create(
                tenant_id=tenant.id,
                scan=scan,
                uid=f"f-cap-{i:02d}",
                check_id=check_id,
                status=StatusChoices.FAIL,
                severity=Severity.high,
                impact=Severity.high,
                check_metadata={},
                raw_result={},
            )
            resource = Resource.objects.create(
                tenant_id=tenant.id,
                provider=scan.provider,
                uid=f"r-cap-{i:02d}",
                name=f"r-cap-{i:02d}",
                metadata="{}",
                details="",
                region="us-east-1",
                service="s",
                type="t::r",
            )
            ResourceFindingMapping.objects.create(
                tenant_id=tenant.id, finding=finding, resource=resource
            )

        mock_provider = Mock(type="aws")
        mock_provider.identity.account = "test"

        totals: dict = {}
        # Patch the cap to a small value AND skip the heavy transform so we
        # only assert on row counts and totals.
        with (
            _patch("tasks.jobs.threatscore_utils.MAX_FINDINGS_PER_CHECK", 5),
            _patch(
                "tasks.jobs.threatscore_utils.FindingOutput.transform_api_finding",
                side_effect=lambda model, provider: Mock(check_id=model.check_id),
            ),
        ):
            result = _load_findings_for_requirement_checks(
                str(tenant.id),
                str(scan.id),
                [check_id],
                mock_provider,
                total_counts_out=totals,
            )

        assert (
            len(result[check_id]) == 5
        ), f"cap=5 should yield exactly 5 loaded findings, got {len(result[check_id])}"
        assert (
            totals[check_id] == 12
        ), f"total_counts_out should report the pre-cap total (12), got {totals[check_id]}"

    def test_only_failed_findings_pushes_down_to_sql(
        self, tenants_fixture, scans_fixture
    ):
        """When ``only_failed_findings=True``, PASS rows are excluded by the
        DB filter, not just visually hidden afterwards.

        Regression for the consistency fix: previously the requirement-level
        ``only_failed`` flag filtered which requirements appeared, but inside
        each rendered requirement the table still showed PASS rows mixed
        with FAIL, which combined with ``MAX_FINDINGS_PER_CHECK`` could
        truncate to 1000 PASS findings and hide the actual failure.
        """
        from unittest.mock import patch as _patch

        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        check_id = "aws_check_only_failed_test"

        # Mix PASS and FAIL so the filter has something to drop.
        for i in range(6):
            status = StatusChoices.FAIL if i % 2 == 0 else StatusChoices.PASS
            finding = Finding.objects.create(
                tenant_id=tenant.id,
                scan=scan,
                uid=f"f-of-{i:02d}",
                check_id=check_id,
                status=status,
                severity=Severity.high,
                impact=Severity.high,
                check_metadata={},
                raw_result={},
            )
            resource = Resource.objects.create(
                tenant_id=tenant.id,
                provider=scan.provider,
                uid=f"r-of-{i:02d}",
                name=f"r-of-{i:02d}",
                metadata="{}",
                details="",
                region="us-east-1",
                service="s",
                type="t::r",
            )
            ResourceFindingMapping.objects.create(
                tenant_id=tenant.id, finding=finding, resource=resource
            )

        mock_provider = Mock(type="aws")
        mock_provider.identity.account = "test"

        totals: dict = {}
        with _patch(
            "tasks.jobs.threatscore_utils.FindingOutput.transform_api_finding",
            side_effect=lambda model, provider: Mock(
                check_id=model.check_id, status=model.status
            ),
        ):
            result = _load_findings_for_requirement_checks(
                str(tenant.id),
                str(scan.id),
                [check_id],
                mock_provider,
                total_counts_out=totals,
                only_failed_findings=True,
            )

        # 3 FAIL + 3 PASS in DB; FAIL-only filter should load just 3.
        loaded = result[check_id]
        assert len(loaded) == 3, f"expected 3 FAIL findings, got {len(loaded)}"
        statuses = {getattr(f, "status", None) for f in loaded}
        assert statuses == {
            StatusChoices.FAIL
        }, f"expected all loaded findings to be FAIL; got statuses {statuses}"
        # total_counts must reflect the FAIL-only total, not the global total.
        assert (
            totals[check_id] == 3
        ), f"total_counts should be FAIL-only (3), got {totals[check_id]}"

    def test_max_findings_per_check_disabled(self, tenants_fixture, scans_fixture):
        """``MAX_FINDINGS_PER_CHECK=0`` disables the cap; load all rows."""
        from unittest.mock import patch as _patch

        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        check_id = "aws_check_uncapped"
        for i in range(8):
            f = Finding.objects.create(
                tenant_id=tenant.id,
                scan=scan,
                uid=f"f-unc-{i:02d}",
                check_id=check_id,
                status=StatusChoices.FAIL,
                severity=Severity.high,
                impact=Severity.high,
                check_metadata={},
                raw_result={},
            )
            r = Resource.objects.create(
                tenant_id=tenant.id,
                provider=scan.provider,
                uid=f"r-unc-{i:02d}",
                name=f"r-unc-{i:02d}",
                metadata="{}",
                details="",
                region="us-east-1",
                service="s",
                type="t::r",
            )
            ResourceFindingMapping.objects.create(
                tenant_id=tenant.id, finding=f, resource=r
            )

        mock_provider = Mock(type="aws")
        mock_provider.identity.account = "test"
        totals: dict = {}
        with (
            _patch("tasks.jobs.threatscore_utils.MAX_FINDINGS_PER_CHECK", 0),
            _patch(
                "tasks.jobs.threatscore_utils.FindingOutput.transform_api_finding",
                side_effect=lambda model, provider: Mock(check_id=model.check_id),
            ),
        ):
            result = _load_findings_for_requirement_checks(
                str(tenant.id),
                str(scan.id),
                [check_id],
                mock_provider,
                total_counts_out=totals,
            )

        assert len(result[check_id]) == 8
        assert totals[check_id] == 8


class TestCleanupStaleTmpOutputDirectories:
    """Unit tests for opportunistic stale cleanup under tmp output root."""

    def test_removes_only_scan_dirs_older_than_ttl(self, tmp_path, monkeypatch):
        """Should remove stale scan directories and keep recent ones."""
        root_dir = tmp_path / "prowler_api_output"

        old_scan_dir = root_dir / "tenant-a" / "scan-old"
        old_scan_dir.mkdir(parents=True)
        (old_scan_dir / "artifact.txt").write_text("old")

        recent_scan_dir = root_dir / "tenant-a" / "scan-recent"
        recent_scan_dir.mkdir(parents=True)
        (recent_scan_dir / "artifact.txt").write_text("recent")

        now = time.time()
        stale_ts = now - ((STALE_TMP_OUTPUT_MAX_AGE_HOURS + 1) * 60 * 60)
        os.utime(old_scan_dir, (stale_ts, stale_ts))

        monkeypatch.setattr(
            "tasks.jobs.report.STALE_TMP_OUTPUT_SAFE_ROOT", root_dir.resolve()
        )
        monkeypatch.setattr(
            "tasks.jobs.report._should_run_stale_cleanup", lambda *_: True
        )
        monkeypatch.setattr(
            "tasks.jobs.report._is_scan_directory_protected", lambda **_: False
        )

        removed = _cleanup_stale_tmp_output_directories(
            str(root_dir), max_age_hours=STALE_TMP_OUTPUT_MAX_AGE_HOURS
        )

        assert removed == 1
        assert not old_scan_dir.exists()
        assert recent_scan_dir.exists()

    def test_skips_current_scan_even_when_stale(self, tmp_path, monkeypatch):
        """Should not delete stale directory for the currently processed scan."""
        root_dir = tmp_path / "prowler_api_output"

        current_scan_dir = root_dir / "tenant-current" / "scan-current"
        current_scan_dir.mkdir(parents=True)
        (current_scan_dir / "artifact.txt").write_text("current")

        other_stale_scan_dir = root_dir / "tenant-other" / "scan-old"
        other_stale_scan_dir.mkdir(parents=True)
        (other_stale_scan_dir / "artifact.txt").write_text("other")

        now = time.time()
        stale_ts = now - ((STALE_TMP_OUTPUT_MAX_AGE_HOURS + 1) * 60 * 60)
        os.utime(current_scan_dir, (stale_ts, stale_ts))
        os.utime(other_stale_scan_dir, (stale_ts, stale_ts))

        monkeypatch.setattr(
            "tasks.jobs.report.STALE_TMP_OUTPUT_SAFE_ROOT", root_dir.resolve()
        )
        monkeypatch.setattr(
            "tasks.jobs.report._should_run_stale_cleanup", lambda *_: True
        )
        monkeypatch.setattr(
            "tasks.jobs.report._is_scan_directory_protected", lambda **_: False
        )

        removed = _cleanup_stale_tmp_output_directories(
            str(root_dir),
            max_age_hours=STALE_TMP_OUTPUT_MAX_AGE_HOURS,
            exclude_scan=("tenant-current", "scan-current"),
        )

        assert removed == 1
        assert current_scan_dir.exists()
        assert not other_stale_scan_dir.exists()

    def test_respects_max_deletions_per_run(self, tmp_path, monkeypatch):
        """Cleanup should stop deleting when max_deletions_per_run is reached."""
        root_dir = tmp_path / "prowler_api_output"

        stale_dir_1 = root_dir / "tenant-a" / "scan-old-1"
        stale_dir_2 = root_dir / "tenant-a" / "scan-old-2"
        stale_dir_1.mkdir(parents=True)
        stale_dir_2.mkdir(parents=True)
        (stale_dir_1 / "artifact.txt").write_text("old-1")
        (stale_dir_2 / "artifact.txt").write_text("old-2")

        now = time.time()
        stale_ts = now - ((STALE_TMP_OUTPUT_MAX_AGE_HOURS + 1) * 60 * 60)
        os.utime(stale_dir_1, (stale_ts, stale_ts))
        os.utime(stale_dir_2, (stale_ts, stale_ts))

        monkeypatch.setattr(
            "tasks.jobs.report.STALE_TMP_OUTPUT_SAFE_ROOT", root_dir.resolve()
        )
        monkeypatch.setattr(
            "tasks.jobs.report._should_run_stale_cleanup", lambda *_: True
        )
        monkeypatch.setattr(
            "tasks.jobs.report._is_scan_directory_protected", lambda **_: False
        )

        removed = _cleanup_stale_tmp_output_directories(
            str(root_dir),
            max_age_hours=STALE_TMP_OUTPUT_MAX_AGE_HOURS,
            max_deletions_per_run=1,
        )

        assert removed == 1
        remaining = sum(
            1 for scan_dir in (stale_dir_1, stale_dir_2) if scan_dir.exists()
        )
        assert remaining == 1

    def test_rejects_non_safe_root(self, tmp_path, monkeypatch):
        """Cleanup must no-op when called with a root outside the allowed safe root."""
        root_dir = tmp_path / "prowler_api_output"
        root_dir.mkdir(parents=True)

        monkeypatch.setattr(
            "tasks.jobs.report.STALE_TMP_OUTPUT_SAFE_ROOT",
            (tmp_path / "another-root").resolve(),
        )

        def _fail_should_run(*_args, **_kwargs):
            raise AssertionError("_should_run_stale_cleanup should not be called")

        monkeypatch.setattr(
            "tasks.jobs.report._should_run_stale_cleanup", _fail_should_run
        )

        removed = _cleanup_stale_tmp_output_directories(str(root_dir), max_age_hours=48)

        assert removed == 0

    def test_ignores_symlink_scan_directories(self, tmp_path, monkeypatch):
        """Symlinked scan directories must never be deleted by cleanup."""
        root_dir = tmp_path / "prowler_api_output"
        stale_real_scan_dir = root_dir / "tenant-a" / "scan-old-real"
        stale_real_scan_dir.mkdir(parents=True)
        (stale_real_scan_dir / "artifact.txt").write_text("old")

        symlink_target = tmp_path / "symlink-target"
        symlink_target.mkdir(parents=True)
        (symlink_target / "artifact.txt").write_text("target")
        symlink_scan_dir = root_dir / "tenant-a" / "scan-link"
        symlink_scan_dir.symlink_to(symlink_target, target_is_directory=True)

        now = time.time()
        stale_ts = now - ((STALE_TMP_OUTPUT_MAX_AGE_HOURS + 1) * 60 * 60)
        os.utime(stale_real_scan_dir, (stale_ts, stale_ts))

        monkeypatch.setattr(
            "tasks.jobs.report.STALE_TMP_OUTPUT_SAFE_ROOT", root_dir.resolve()
        )
        monkeypatch.setattr(
            "tasks.jobs.report._should_run_stale_cleanup", lambda *_: True
        )
        monkeypatch.setattr(
            "tasks.jobs.report._is_scan_directory_protected", lambda **_: False
        )

        removed = _cleanup_stale_tmp_output_directories(
            str(root_dir), max_age_hours=STALE_TMP_OUTPUT_MAX_AGE_HOURS
        )

        assert removed == 1
        assert not stale_real_scan_dir.exists()
        assert symlink_scan_dir.exists()
        assert symlink_target.exists()

    def test_handles_internal_exception_without_propagating(
        self, tmp_path, monkeypatch
    ):
        """Cleanup errors must be swallowed so callers are not interrupted."""
        root_dir = tmp_path / "prowler_api_output"
        stale_scan_dir = root_dir / "tenant-a" / "scan-old"
        stale_scan_dir.mkdir(parents=True)

        now = time.time()
        stale_ts = now - ((STALE_TMP_OUTPUT_MAX_AGE_HOURS + 1) * 60 * 60)
        os.utime(stale_scan_dir, (stale_ts, stale_ts))

        monkeypatch.setattr(
            "tasks.jobs.report.STALE_TMP_OUTPUT_SAFE_ROOT", root_dir.resolve()
        )
        monkeypatch.setattr(
            "tasks.jobs.report._should_run_stale_cleanup", lambda *_: True
        )

        def _raise(*_args, **_kwargs):
            raise RuntimeError("db timeout")

        monkeypatch.setattr("tasks.jobs.report._is_scan_directory_protected", _raise)

        removed = _cleanup_stale_tmp_output_directories(
            str(root_dir), max_age_hours=STALE_TMP_OUTPUT_MAX_AGE_HOURS
        )

        assert removed == 0
        assert stale_scan_dir.exists()

    def test_safe_root_follows_custom_tmp_output_directory(self, tmp_path, monkeypatch):
        """Custom DJANGO_TMP_OUTPUT_DIRECTORY must be honored as the safe root."""
        from tasks.jobs import report as report_module

        custom_root = tmp_path / "custom_tmp_output"
        custom_root.mkdir(parents=True)

        monkeypatch.setattr(
            report_module, "DJANGO_TMP_OUTPUT_DIRECTORY", str(custom_root)
        )

        resolved_root = report_module._resolve_stale_tmp_safe_root()
        assert resolved_root == custom_root.resolve()

        stale_scan_dir = custom_root / "tenant-a" / "scan-old"
        stale_scan_dir.mkdir(parents=True)
        (stale_scan_dir / "artifact.txt").write_text("old")

        stale_ts = time.time() - ((STALE_TMP_OUTPUT_MAX_AGE_HOURS + 1) * 60 * 60)
        os.utime(stale_scan_dir, (stale_ts, stale_ts))

        monkeypatch.setattr(report_module, "STALE_TMP_OUTPUT_SAFE_ROOT", resolved_root)
        monkeypatch.setattr(
            "tasks.jobs.report._should_run_stale_cleanup", lambda *_: True
        )
        monkeypatch.setattr(
            "tasks.jobs.report._is_scan_directory_protected", lambda **_: False
        )

        removed = _cleanup_stale_tmp_output_directories(
            str(custom_root), max_age_hours=STALE_TMP_OUTPUT_MAX_AGE_HOURS
        )

        assert removed == 1
        assert not stale_scan_dir.exists()

    @pytest.mark.parametrize(
        "forbidden_root",
        ["/", "/tmp", "/var", "/var/tmp", "/home", "/root", "/etc", "/usr"],
    )
    def test_safe_root_rejects_forbidden_system_roots(
        self, forbidden_root, monkeypatch
    ):
        """Cleanup must refuse to operate against shared system roots."""
        from tasks.jobs import report as report_module

        monkeypatch.setattr(
            report_module, "DJANGO_TMP_OUTPUT_DIRECTORY", forbidden_root
        )

        assert report_module._resolve_stale_tmp_safe_root() is None

    def test_skips_cleanup_when_safe_root_is_none(self, tmp_path, monkeypatch):
        """A None safe root (forbidden config) must short-circuit the cleanup."""
        root_dir = tmp_path / "prowler_api_output"
        root_dir.mkdir(parents=True)

        monkeypatch.setattr("tasks.jobs.report.STALE_TMP_OUTPUT_SAFE_ROOT", None)

        def _fail_should_run(*_args, **_kwargs):
            raise AssertionError("_should_run_stale_cleanup should not be called")

        monkeypatch.setattr(
            "tasks.jobs.report._should_run_stale_cleanup", _fail_should_run
        )

        removed = _cleanup_stale_tmp_output_directories(
            str(root_dir), max_age_hours=STALE_TMP_OUTPUT_MAX_AGE_HOURS
        )

        assert removed == 0


class TestStaleCleanupProtectionHelpers:
    """Unit tests for stale cleanup helper guard logic."""

    def test_should_run_cleanup_is_throttled(self, tmp_path):
        root_dir = tmp_path / "prowler_api_output"
        root_dir.mkdir(parents=True)

        assert _should_run_stale_cleanup(root_dir, throttle_seconds=3600) is True
        assert _should_run_stale_cleanup(root_dir, throttle_seconds=3600) is False

        lock_file = root_dir / STALE_TMP_OUTPUT_LOCK_FILE_NAME
        lock_file.write_text(str(int(time.time()) - 7200), encoding="ascii")

        assert _should_run_stale_cleanup(root_dir, throttle_seconds=3600) is True

    @patch("tasks.jobs.report.fcntl.flock", side_effect=BlockingIOError)
    def test_should_run_cleanup_returns_false_when_lock_is_busy(
        self, _mock_flock, tmp_path
    ):
        root_dir = tmp_path / "prowler_api_output"
        root_dir.mkdir(parents=True)

        assert _should_run_stale_cleanup(root_dir, throttle_seconds=3600) is False

    @patch("tasks.jobs.report.Scan.all_objects.using")
    def test_is_scan_directory_protected_for_executing_scan(
        self, mock_scan_using, tmp_path
    ):
        scan_id = str(uuid.uuid4())
        scan_path = tmp_path / scan_id
        scan_path.mkdir(parents=True)
        mock_scan_using.return_value.filter.return_value.only.return_value.first.return_value = Mock(
            state=StateChoices.EXECUTING, output_location=None
        )

        assert (
            _is_scan_directory_protected(
                tenant_id="tenant-a",
                scan_id=scan_id,
                scan_path=scan_path,
            )
            is True
        )

    @patch("tasks.jobs.report.Scan.all_objects.using")
    def test_is_scan_directory_protected_for_local_output(
        self, mock_scan_using, tmp_path
    ):
        scan_id = str(uuid.uuid4())
        scan_path = tmp_path / scan_id
        scan_path.mkdir(parents=True)
        local_output_path = scan_path / "outputs.zip"
        mock_scan_using.return_value.filter.return_value.only.return_value.first.return_value = Mock(
            state=StateChoices.COMPLETED, output_location=str(local_output_path)
        )

        assert (
            _is_scan_directory_protected(
                tenant_id="tenant-a",
                scan_id=scan_id,
                scan_path=scan_path.resolve(),
            )
            is True
        )

    @patch("tasks.jobs.report.Scan.all_objects.using")
    def test_is_scan_directory_not_protected_for_s3_output(
        self, mock_scan_using, tmp_path
    ):
        scan_id = str(uuid.uuid4())
        scan_path = tmp_path / scan_id
        scan_path.mkdir(parents=True)
        mock_scan_using.return_value.filter.return_value.only.return_value.first.return_value = Mock(
            state=StateChoices.COMPLETED,
            output_location="s3://bucket/path/report.zip",
        )

        assert (
            _is_scan_directory_protected(
                tenant_id="tenant-a",
                scan_id=scan_id,
                scan_path=scan_path,
            )
            is False
        )


@pytest.mark.django_db
class TestGenerateThreatscoreReportFunction:
    """Test suite for generate_threatscore_report function."""

    @patch("tasks.jobs.reports.base.initialize_prowler_provider")
    def test_generate_threatscore_report_exception_handling(
        self,
        mock_initialize_provider,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test that exceptions during report generation are properly handled."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        mock_initialize_provider.side_effect = Exception("Test exception")

        with pytest.raises(Exception) as exc_info:
            generate_threatscore_report(
                tenant_id=str(tenant.id),
                scan_id=str(scan.id),
                compliance_id="prowler_threatscore_aws",
                output_path="/tmp/test_report.pdf",
                provider_id=str(provider.id),
            )

        assert "Test exception" in str(exc_info.value)


@pytest.mark.django_db
class TestGenerateComplianceReportsOptimized:
    """Test suite for generate_compliance_reports function."""

    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_threatscore_report")
    @patch("tasks.jobs.report.generate_ens_report")
    @patch("tasks.jobs.report.generate_nis2_report")
    def test_no_findings_returns_early_for_both_reports(
        self,
        mock_nis2,
        mock_ens,
        mock_threatscore,
        mock_upload,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test that function returns early when scan has no findings."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        result = generate_compliance_reports(
            tenant_id=str(tenant.id),
            scan_id=str(scan.id),
            provider_id=str(provider.id),
            generate_threatscore=True,
            generate_ens=True,
            generate_nis2=True,
        )

        assert result["threatscore"]["upload"] is False
        assert result["ens"]["upload"] is False
        assert result["nis2"]["upload"] is False

        mock_threatscore.assert_not_called()
        mock_ens.assert_not_called()
        mock_nis2.assert_not_called()

    @patch(
        "tasks.jobs.report._cleanup_stale_tmp_output_directories",
        side_effect=RuntimeError("cleanup boom"),
    )
    def test_cleanup_exception_does_not_break_no_findings_flow(self, _mock_cleanup):
        """Unexpected cleanup failures must not abort report generation."""
        random_tenant = str(uuid.uuid4())
        random_scan = str(uuid.uuid4())
        random_provider = str(uuid.uuid4())

        with patch("tasks.jobs.report.ScanSummary.objects.filter") as mock_filter:
            mock_filter.return_value.exists.return_value = False
            result = generate_compliance_reports(
                tenant_id=random_tenant,
                scan_id=random_scan,
                provider_id=random_provider,
                generate_threatscore=True,
                generate_ens=False,
                generate_nis2=False,
                generate_csa=False,
                generate_cis=False,
            )

        assert result["threatscore"] == {"upload": False, "path": ""}

    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_cis_report")
    def test_no_findings_returns_flat_cis_entry(
        self,
        mock_cis,
        mock_upload,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Scan with no findings and ``generate_cis=True`` must yield a flat
        ``{"upload": False, "path": ""}`` entry, consistent with the other
        frameworks (no nested dict, no sentinel keys)."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        result = generate_compliance_reports(
            tenant_id=str(tenant.id),
            scan_id=str(scan.id),
            provider_id=str(provider.id),
            generate_threatscore=False,
            generate_ens=False,
            generate_nis2=False,
            generate_csa=False,
            generate_cis=True,
        )

        assert result["cis"] == {"upload": False, "path": ""}
        mock_cis.assert_not_called()

    @patch("api.utils.initialize_prowler_provider")
    @patch("tasks.jobs.report.rmtree")
    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_cis_report")
    @patch("tasks.jobs.report.generate_csa_report")
    @patch("tasks.jobs.report.generate_nis2_report")
    @patch("tasks.jobs.report.generate_ens_report")
    @patch("tasks.jobs.report.generate_threatscore_report")
    @patch("tasks.jobs.report._generate_compliance_output_directory")
    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    @patch("tasks.jobs.report.Provider.objects.get")
    @patch("tasks.jobs.report.ScanSummary.objects.filter")
    def test_findings_cache_eviction_after_framework(
        self,
        mock_scan_summary_filter,
        mock_provider_get,
        mock_get_bulk,
        mock_aggregate_stats,
        mock_generate_output_dir,
        mock_threatscore,
        mock_ens,
        mock_nis2,
        mock_csa,
        mock_cis,
        mock_upload_to_s3,
        mock_rmtree,
        mock_init_provider,
    ):
        """After each framework finishes, exclusive entries are evicted.

        Threat scenario for PROWLER-1733: the shared ``findings_cache`` used
        to grow monotonically through all 5 frameworks. With the new
        eviction logic, check_ids only used by ThreatScore are dropped when
        ThreatScore finishes, before ENS runs.
        """
        from types import SimpleNamespace
        from tasks.jobs import report as report_mod

        mock_scan_summary_filter.return_value.exists.return_value = True
        mock_provider_get.return_value = Mock(uid="provider-uid", provider="aws")
        # ThreatScore consumes {tsc_only, shared}; ENS consumes {ens_only,
        # shared}. After ThreatScore evicts, tsc_only must be gone but
        # shared and ens_only must remain.
        mock_get_bulk.return_value = {
            "prowler_threatscore_aws": SimpleNamespace(
                Requirements=[SimpleNamespace(Checks=["tsc_only", "shared"])]
            ),
            "ens_rd2022_aws": SimpleNamespace(
                Requirements=[SimpleNamespace(Checks=["ens_only", "shared"])]
            ),
        }
        mock_aggregate_stats.return_value = {}
        mock_generate_output_dir.return_value = "/tmp/tenant/scan/x/prowler-out"
        mock_upload_to_s3.return_value = "s3://bucket/tenant/scan/x/report.pdf"
        mock_init_provider.return_value = Mock(name="prowler_provider")

        # Seed the cache as if both frameworks had already loaded their
        # findings. We mutate it indirectly: each generator wrapper is a
        # Mock: make ThreatScore populate the cache, and have ENS observe
        # the state at call time so we can introspect post-eviction.
        observed_state: dict = {}

        def _threatscore_side_effect(**kwargs):
            cache = kwargs["findings_cache"]
            cache["tsc_only"] = ["tsc-finding"]
            cache["shared"] = ["shared-finding"]

        def _ens_side_effect(**kwargs):
            # ENS runs AFTER threatscore's _evict_after_framework("threatscore").
            observed_state["cache_keys_when_ens_runs"] = set(
                kwargs["findings_cache"].keys()
            )
            kwargs["findings_cache"]["ens_only"] = ["ens-finding"]

        mock_threatscore.side_effect = _threatscore_side_effect
        mock_ens.side_effect = _ens_side_effect

        report_mod.generate_compliance_reports(
            tenant_id=str(uuid.uuid4()),
            scan_id=str(uuid.uuid4()),
            provider_id=str(uuid.uuid4()),
            generate_threatscore=True,
            generate_ens=True,
            generate_nis2=False,
            generate_csa=False,
            generate_cis=False,
        )

        # ``tsc_only`` was exclusive to ThreatScore → evicted before ENS ran.
        # ``shared`` is still pending for ENS → must remain.
        assert (
            "tsc_only" not in observed_state["cache_keys_when_ens_runs"]
        ), "tsc_only should have been evicted before ENS ran"
        assert (
            "shared" in observed_state["cache_keys_when_ens_runs"]
        ), "shared must remain in cache because ENS still needs it"

    @patch("tasks.jobs.report.initialize_prowler_provider")
    @patch("tasks.jobs.report.rmtree")
    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_cis_report")
    @patch("tasks.jobs.report.generate_csa_report")
    @patch("tasks.jobs.report.generate_nis2_report")
    @patch("tasks.jobs.report.generate_ens_report")
    @patch("tasks.jobs.report.generate_threatscore_report")
    @patch("tasks.jobs.report._generate_compliance_output_directory")
    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    @patch("tasks.jobs.report.Provider.objects.get")
    @patch("tasks.jobs.report.ScanSummary.objects.filter")
    def test_prowler_provider_initialized_once(
        self,
        mock_scan_summary_filter,
        mock_provider_get,
        mock_get_bulk,
        mock_aggregate_stats,
        mock_generate_output_dir,
        mock_threatscore,
        mock_ens,
        mock_nis2,
        mock_csa,
        mock_cis,
        mock_upload_to_s3,
        mock_rmtree,
        mock_init_provider,
    ):
        """``initialize_prowler_provider`` must be called exactly once for
        the whole batch (PROWLER-1733). Previously each generator re-init'd
        the SDK provider in ``_load_compliance_data`` → 5 inits per scan.
        """
        mock_scan_summary_filter.return_value.exists.return_value = True
        mock_provider_get.return_value = Mock(uid="provider-uid", provider="aws")
        # CIS variant discovery needs at least one cis_* key.
        mock_get_bulk.return_value = {"cis_6.0_aws": Mock()}
        mock_aggregate_stats.return_value = {}
        mock_generate_output_dir.return_value = "/tmp/tenant/scan/x/prowler-out"
        mock_upload_to_s3.return_value = "s3://bucket/tenant/scan/x/report.pdf"
        mock_init_provider.return_value = Mock(name="prowler_provider")

        generate_compliance_reports(
            tenant_id=str(uuid.uuid4()),
            scan_id=str(uuid.uuid4()),
            provider_id=str(uuid.uuid4()),
            generate_threatscore=True,
            generate_ens=True,
            generate_nis2=True,
            generate_csa=True,
            generate_cis=True,
        )

        # All 5 wrappers were invoked once each…
        mock_threatscore.assert_called_once()
        mock_ens.assert_called_once()
        mock_nis2.assert_called_once()
        mock_csa.assert_called_once()
        mock_cis.assert_called_once()
        # …but the SDK provider was initialized only once.
        assert mock_init_provider.call_count == 1, (
            f"expected 1 init, got {mock_init_provider.call_count} "
            f"(prowler_provider must be shared across reports)"
        )

        # The shared instance must reach every wrapper as kwargs.
        shared = mock_init_provider.return_value
        for mock_wrapper in (
            mock_threatscore,
            mock_ens,
            mock_nis2,
            mock_csa,
            mock_cis,
        ):
            _, call_kwargs = mock_wrapper.call_args
            assert call_kwargs.get("prowler_provider") is shared

    @patch("tasks.jobs.report.rmtree")
    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_threatscore_report")
    @patch("tasks.jobs.report._generate_compliance_output_directory")
    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    @patch("tasks.jobs.report.Provider.objects.get")
    @patch("tasks.jobs.report.ScanSummary.objects.filter")
    def test_cleanup_runs_when_supported_reports_upload_successfully(
        self,
        mock_scan_summary_filter,
        mock_provider_get,
        mock_get_bulk,
        mock_aggregate_stats,
        mock_generate_output_dir,
        mock_threatscore,
        mock_upload_to_s3,
        mock_rmtree,
    ):
        """Cleanup must run when all generated (supported) reports are uploaded."""
        mock_scan_summary_filter.return_value.exists.return_value = True
        mock_provider_get.return_value = Mock(uid="provider-uid", provider="m365")
        mock_get_bulk.return_value = {}
        mock_aggregate_stats.return_value = {}
        mock_generate_output_dir.return_value = (
            "/tmp/tenant/scan/threatscore/prowler-output-provider-20240101000000"
        )
        mock_upload_to_s3.return_value = (
            "s3://bucket/tenant/scan/threatscore/report.pdf"
        )

        result = generate_compliance_reports(
            tenant_id=str(uuid.uuid4()),
            scan_id=str(uuid.uuid4()),
            provider_id=str(uuid.uuid4()),
            generate_threatscore=True,
            generate_ens=True,
            generate_nis2=True,
            generate_csa=True,
            generate_cis=True,
        )

        assert result["threatscore"]["upload"] is True
        assert result["ens"]["upload"] is False
        assert result["nis2"]["upload"] is False
        assert result["csa"]["upload"] is False
        assert result["cis"] == {"upload": False, "path": ""}
        mock_generate_output_dir.assert_called_once()
        mock_threatscore.assert_called_once()
        mock_rmtree.assert_called_once()

    @patch("tasks.jobs.report.rmtree")
    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_threatscore_report")
    @patch("tasks.jobs.report._generate_compliance_output_directory")
    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    @patch("tasks.jobs.report.Provider.objects.get")
    @patch("tasks.jobs.report.ScanSummary.objects.filter")
    def test_cleanup_skipped_when_supported_upload_fails(
        self,
        mock_scan_summary_filter,
        mock_provider_get,
        mock_get_bulk,
        mock_aggregate_stats,
        mock_generate_output_dir,
        mock_threatscore,
        mock_upload_to_s3,
        mock_rmtree,
    ):
        """Cleanup must not run when a generated report upload fails."""
        mock_scan_summary_filter.return_value.exists.return_value = True
        mock_provider_get.return_value = Mock(uid="provider-uid", provider="m365")
        mock_get_bulk.return_value = {}
        mock_aggregate_stats.return_value = {}
        mock_generate_output_dir.return_value = (
            "/tmp/tenant/scan/threatscore/prowler-output-provider-20240101000000"
        )
        mock_upload_to_s3.return_value = None

        result = generate_compliance_reports(
            tenant_id=str(uuid.uuid4()),
            scan_id=str(uuid.uuid4()),
            provider_id=str(uuid.uuid4()),
            generate_threatscore=True,
            generate_ens=True,
            generate_nis2=True,
            generate_csa=True,
            generate_cis=True,
        )

        assert result["threatscore"]["upload"] is False
        assert result["cis"] == {"upload": False, "path": ""}
        mock_generate_output_dir.assert_called_once()
        mock_threatscore.assert_called_once()
        mock_rmtree.assert_not_called()


@pytest.mark.django_db
class TestGenerateComplianceReportsCIS:
    """Test suite covering the CIS branch of generate_compliance_reports."""

    def _force_scan_has_findings(self, monkeypatch):
        """Bypass the ScanSummary.exists() early-return guard."""

        class _FakeManager:
            def filter(self, **kwargs):
                class _Q:
                    def exists(self):
                        return True

                return _Q()

        monkeypatch.setattr("tasks.jobs.report.ScanSummary.objects", _FakeManager())

    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_cis_report")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    def test_cis_picks_latest_version(
        self,
        mock_get_bulk,
        mock_cis,
        mock_upload,
        mock_stats,
        monkeypatch,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """CIS branch should generate a single PDF for the highest version.

        The returned ``results["cis"]`` must have the same flat shape as the
        other single-version frameworks (``{"upload", "path"}``) — the picked
        variant is an internal detail and is not exposed in the result.
        """
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        self._force_scan_has_findings(monkeypatch)

        mock_stats.return_value = {}
        # Multiple CIS variants + a non-CIS framework that must be ignored.
        # Includes 1.10 to verify the selection is not lexicographic.
        mock_get_bulk.return_value = {
            "cis_1.4_aws": Mock(),
            "cis_1.10_aws": Mock(),
            "cis_2.0_aws": Mock(),
            "cis_5.0_aws": Mock(),
            "ens_rd2022_aws": Mock(),
        }
        mock_upload.return_value = "s3://bucket/path"

        result = generate_compliance_reports(
            tenant_id=str(tenant.id),
            scan_id=str(scan.id),
            provider_id=str(provider.id),
            generate_threatscore=False,
            generate_ens=False,
            generate_nis2=False,
            generate_csa=False,
            generate_cis=True,
        )

        # Exactly one call for the latest version, never for older variants
        # or non-CIS frameworks.
        assert mock_cis.call_count == 1
        assert mock_cis.call_args.kwargs["compliance_id"] == "cis_5.0_aws"

        assert result["cis"]["upload"] is True
        assert result["cis"]["path"] == "s3://bucket/path"
        assert "compliance_id" not in result["cis"]

    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_cis_report")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    def test_cis_latest_variant_failure_captured_in_results(
        self,
        mock_get_bulk,
        mock_cis,
        mock_upload,
        mock_stats,
        monkeypatch,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """A failure in the latest CIS variant must be surfaced in the flat results entry."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        self._force_scan_has_findings(monkeypatch)

        mock_stats.return_value = {}
        mock_get_bulk.return_value = {
            "cis_1.4_aws": Mock(),
            "cis_5.0_aws": Mock(),
        }
        mock_cis.side_effect = RuntimeError("boom")

        result = generate_compliance_reports(
            tenant_id=str(tenant.id),
            scan_id=str(scan.id),
            provider_id=str(provider.id),
            generate_threatscore=False,
            generate_ens=False,
            generate_nis2=False,
            generate_csa=False,
            generate_cis=True,
        )

        # Only the latest variant is attempted; its failure lands in a flat
        # entry keyed under "cis" with the same shape as sibling frameworks.
        assert mock_cis.call_count == 1
        assert result["cis"]["upload"] is False
        assert result["cis"]["error"] == "boom"
        assert "compliance_id" not in result["cis"]

    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_cis_report")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    def test_cis_provider_without_cis_skipped_cleanly(
        self,
        mock_get_bulk,
        mock_cis,
        mock_upload,
        mock_stats,
        monkeypatch,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """When ``Compliance.get_bulk`` returns no CIS entry the CIS branch
        must skip cleanly and record a flat ``{"upload": False, "path": ""}``
        entry — no hard-coded provider whitelist is consulted."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        self._force_scan_has_findings(monkeypatch)
        mock_stats.return_value = {}
        # No ``cis_*`` keys in the bulk → no variant picked.
        mock_get_bulk.return_value = {"ens_rd2022_aws": Mock()}

        result = generate_compliance_reports(
            tenant_id=str(tenant.id),
            scan_id=str(scan.id),
            provider_id=str(provider.id),
            generate_threatscore=False,
            generate_ens=False,
            generate_nis2=False,
            generate_csa=False,
            generate_cis=True,
        )

        assert result["cis"] == {"upload": False, "path": ""}
        mock_cis.assert_not_called()

    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report._generate_compliance_output_directory")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    def test_cis_output_directory_failure_is_captured(
        self,
        mock_get_bulk,
        mock_generate_output_dir,
        mock_stats,
        monkeypatch,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """CIS output dir errors must be captured in results (not raised)."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        self._force_scan_has_findings(monkeypatch)
        mock_stats.return_value = {}
        mock_get_bulk.return_value = {"cis_5.0_aws": Mock()}
        mock_generate_output_dir.side_effect = RuntimeError("dir boom")

        result = generate_compliance_reports(
            tenant_id=str(tenant.id),
            scan_id=str(scan.id),
            provider_id=str(provider.id),
            generate_threatscore=False,
            generate_ens=False,
            generate_nis2=False,
            generate_csa=False,
            generate_cis=True,
        )

        assert result["cis"]["upload"] is False
        assert result["cis"]["error"] == "dir boom"


class TestPickLatestCisVariant:
    """Unit tests for `_pick_latest_cis_variant` helper."""

    def test_empty_returns_none(self):
        assert _pick_latest_cis_variant([]) is None

    def test_single_variant(self):
        assert _pick_latest_cis_variant(["cis_5.0_aws"]) == "cis_5.0_aws"

    def test_numeric_not_lexicographic(self):
        """1.10 must beat 1.2 (lex sort would pick 1.2)."""
        variants = ["cis_1.2_kubernetes", "cis_1.10_kubernetes"]
        assert _pick_latest_cis_variant(variants) == "cis_1.10_kubernetes"

    def test_major_version_wins(self):
        variants = ["cis_1.4_aws", "cis_2.0_aws", "cis_5.0_aws", "cis_6.0_aws"]
        assert _pick_latest_cis_variant(variants) == "cis_6.0_aws"

    def test_minor_version_breaks_tie(self):
        variants = ["cis_3.0_aws", "cis_3.1_aws", "cis_2.9_aws"]
        assert _pick_latest_cis_variant(variants) == "cis_3.1_aws"

    def test_three_part_version(self):
        """Versions like 3.0.1 must win over 3.0."""
        variants = ["cis_3.0_aws", "cis_3.0.1_aws"]
        assert _pick_latest_cis_variant(variants) == "cis_3.0.1_aws"

    def test_malformed_names_ignored(self):
        variants = ["notcis_1.0_aws", "cis_abc_aws", "cis_5.0_aws"]
        assert _pick_latest_cis_variant(variants) == "cis_5.0_aws"

    def test_only_malformed_returns_none(self):
        variants = ["notcis_1.0_aws", "cis_abc_aws"]
        assert _pick_latest_cis_variant(variants) is None

    def test_multidigit_provider_name(self):
        """Provider name with underscores (e.g. googleworkspace) must parse."""
        variants = ["cis_1.3_googleworkspace"]
        assert _pick_latest_cis_variant(variants) == "cis_1.3_googleworkspace"

    def test_accepts_iterator(self):
        """The helper must accept any iterable, not just lists."""

        def _gen():
            yield "cis_1.4_aws"
            yield "cis_5.0_aws"

        assert _pick_latest_cis_variant(_gen()) == "cis_5.0_aws"

    def test_rejects_single_integer_version(self):
        """The regex requires at least one dotted component. ``cis_5_aws``
        without a minor version is malformed per the backend contract."""
        assert _pick_latest_cis_variant(["cis_5_aws"]) is None

    def test_rejects_trailing_dot(self):
        """Inputs like ``cis_5._aws`` must be rejected at the regex stage
        instead of silently normalising to ``(5, 0)``."""
        assert _pick_latest_cis_variant(["cis_5._aws", "cis_1.0_aws"]) == "cis_1.0_aws"

    def test_rejects_lone_dot_version(self):
        """``cis_._aws`` has no numeric component and must be skipped."""
        assert _pick_latest_cis_variant(["cis_._aws", "cis_1.0_aws"]) == "cis_1.0_aws"


class TestOptimizationImprovements:
    """Test suite for optimization-related functionality."""

    def test_chart_color_constants_are_strings(self):
        """Verify chart color constants are valid hex color strings."""
        assert CHART_COLOR_GREEN_1.startswith("#")
        assert CHART_COLOR_GREEN_2.startswith("#")
        assert CHART_COLOR_YELLOW.startswith("#")
        assert CHART_COLOR_ORANGE.startswith("#")
        assert CHART_COLOR_RED.startswith("#")

    def test_color_constants_are_color_objects(self):
        """Verify color constants are Color objects."""
        assert isinstance(COLOR_BLUE, colors.Color)
        assert isinstance(COLOR_HIGH_RISK, colors.Color)
        assert isinstance(COLOR_SAFE, colors.Color)
        assert isinstance(COLOR_ENS_ALTO, colors.Color)
        assert isinstance(COLOR_NIS2_PRIMARY, colors.Color)
