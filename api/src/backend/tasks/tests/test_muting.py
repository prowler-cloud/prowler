from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from api.models import Finding, MuteRule, Scan, StateChoices
from prowler.lib.check.models import Severity
from prowler.lib.outputs.finding import Status
from tasks.jobs.muting import (
    mute_findings_in_latest_scans,
    reconcile_scan_mute_rules,
)


def _create_finding(scan: Scan, uid: str) -> Finding:
    return Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=uid,
        scan=scan,
        status=Status.FAIL,
        status_extended="Test finding",
        impact=Severity.high,
        severity=Severity.high,
        raw_result={},
        check_id="test_check",
        check_metadata={"CheckId": "test_check"},
        muted=False,
    )


def _create_mute_rule(tenant_id, user, finding_uids, *, enabled=True) -> MuteRule:
    return MuteRule.objects.create(
        tenant_id=tenant_id,
        name=f"Mute rule {uuid4()}",
        reason="Approved exception",
        enabled=enabled,
        created_by=user,
        finding_uids=finding_uids,
    )


@pytest.mark.django_db
class TestMuteFindingsInLatestScans:
    def test_mutes_latest_scan_and_leaves_older_scan_unchanged(
        self, scans_fixture, create_test_user
    ):
        latest_scan = scans_fixture[0]
        older_scan = Scan.objects.create(
            tenant_id=latest_scan.tenant_id,
            provider=latest_scan.provider,
            name="Older scan",
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            started_at=datetime.now(UTC) - timedelta(days=1),
            completed_at=datetime.now(UTC) - timedelta(days=1),
        )
        uid = "latest-scan-only"
        older_finding = _create_finding(older_scan, uid)
        latest_finding = _create_finding(latest_scan, uid)
        mute_rule = _create_mute_rule(latest_scan.tenant_id, create_test_user, [uid])

        result = mute_findings_in_latest_scans(
            str(latest_scan.tenant_id),
            str(mute_rule.id),
            [str(latest_scan.provider_id)],
        )

        older_finding.refresh_from_db()
        latest_finding.refresh_from_db()
        assert older_finding.muted is False
        assert latest_finding.muted is True
        assert latest_finding.muted_at == mute_rule.inserted_at
        assert latest_finding.muted_reason == mute_rule.reason
        assert result == {
            "findings_muted": 1,
            "rule_id": str(mute_rule.id),
            "scan_ids": [str(latest_scan.id)],
        }

    def test_mutes_one_latest_scan_per_provider(self, scans_fixture, create_test_user):
        first_scan, second_scan, _ = scans_fixture
        uid = "shared-selected-uid"
        first_finding = _create_finding(first_scan, uid)
        second_finding = _create_finding(second_scan, uid)
        mute_rule = _create_mute_rule(first_scan.tenant_id, create_test_user, [uid])

        result = mute_findings_in_latest_scans(
            str(first_scan.tenant_id),
            str(mute_rule.id),
            [str(first_scan.provider_id), str(second_scan.provider_id)],
        )

        first_finding.refresh_from_db()
        second_finding.refresh_from_db()
        assert first_finding.muted is True
        assert second_finding.muted is True
        assert result["findings_muted"] == 2
        assert set(result["scan_ids"]) == {str(first_scan.id), str(second_scan.id)}

    def test_provider_without_completed_scan_does_nothing(
        self, tenants_fixture, provider_factory, create_test_user
    ):
        tenant = tenants_fixture[0]
        provider = provider_factory()
        mute_rule = _create_mute_rule(
            tenant.id, create_test_user, ["future-scan-finding"]
        )

        result = mute_findings_in_latest_scans(
            str(tenant.id), str(mute_rule.id), [str(provider.id)]
        )

        assert result == {
            "findings_muted": 0,
            "rule_id": str(mute_rule.id),
            "scan_ids": [],
        }

    def test_retry_does_not_report_changed_scans_twice(
        self, scans_fixture, create_test_user
    ):
        scan = scans_fixture[0]
        finding = _create_finding(scan, "idempotent-mute")
        mute_rule = _create_mute_rule(scan.tenant_id, create_test_user, [finding.uid])
        args = (
            str(scan.tenant_id),
            str(mute_rule.id),
            [str(scan.provider_id)],
        )

        first_result = mute_findings_in_latest_scans(*args)
        second_result = mute_findings_in_latest_scans(*args)

        assert first_result["scan_ids"] == [str(scan.id)]
        assert second_result["findings_muted"] == 0
        assert second_result["scan_ids"] == []

    def test_does_not_cross_tenant_boundary(
        self, tenants_fixture, provider_factory, create_test_user
    ):
        tenant = tenants_fixture[0]
        other_tenant = tenants_fixture[2]
        other_provider = provider_factory(tenant=other_tenant)
        other_scan = Scan.objects.create(
            tenant_id=other_tenant.id,
            provider=other_provider,
            name="Other tenant scan",
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        other_finding = _create_finding(other_scan, "tenant-isolated-uid")
        mute_rule = _create_mute_rule(tenant.id, create_test_user, [other_finding.uid])

        result = mute_findings_in_latest_scans(
            str(tenant.id), str(mute_rule.id), [str(other_provider.id)]
        )

        other_finding.refresh_from_db()
        assert other_finding.muted is False
        assert result["scan_ids"] == []

    def test_nonexistent_rule_raises(self, tenants_fixture):
        with pytest.raises(MuteRule.DoesNotExist):
            mute_findings_in_latest_scans(str(tenants_fixture[0].id), str(uuid4()), [])


@pytest.mark.django_db
class TestReconcileScanMuteRules:
    def test_applies_only_enabled_rules_to_requested_scan(
        self, scans_fixture, create_test_user
    ):
        scan = scans_fixture[0]
        active_finding = _create_finding(scan, "active-rule-uid")
        disabled_finding = _create_finding(scan, "disabled-rule-uid")
        active_rule = _create_mute_rule(
            scan.tenant_id, create_test_user, [active_finding.uid]
        )
        _create_mute_rule(
            scan.tenant_id,
            create_test_user,
            [disabled_finding.uid],
            enabled=False,
        )
        older_scan = Scan.objects.create(
            tenant_id=scan.tenant_id,
            provider=scan.provider,
            name="Older matching scan",
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            started_at=datetime.now(UTC) - timedelta(days=1),
            completed_at=datetime.now(UTC) - timedelta(days=1),
        )
        older_finding = _create_finding(older_scan, active_finding.uid)

        result = reconcile_scan_mute_rules(str(scan.tenant_id), str(scan.id))

        active_finding.refresh_from_db()
        disabled_finding.refresh_from_db()
        older_finding.refresh_from_db()
        assert active_finding.muted is True
        assert active_finding.muted_at == active_rule.inserted_at
        assert disabled_finding.muted is False
        assert older_finding.muted is False
        assert result == {"findings_muted": 1, "scan_id": str(scan.id)}
