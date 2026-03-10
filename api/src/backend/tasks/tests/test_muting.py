from datetime import datetime, timezone
from uuid import uuid4

import pytest
from django.core.exceptions import ObjectDoesNotExist
from tasks.jobs.muting import mute_historical_findings

from api.models import Finding, MuteRule
from prowler.lib.check.models import Severity
from prowler.lib.outputs.finding import Status


@pytest.mark.django_db
class TestMuteHistoricalFindings:
    """
    Test suite for the mute_historical_findings function.

    This class tests the batch processing of findings to update their muted status
    based on MuteRule criteria.
    """

    @pytest.fixture(scope="function")
    def test_user(self, create_test_user):
        """Create a test user for mute rule creation."""
        return create_test_user

    @pytest.fixture(scope="function")
    def mute_rule_with_findings(self, tenants_fixture, findings_fixture, test_user):
        """
        Create a mute rule that targets the first finding in the fixture.
        """
        tenant = tenants_fixture[0]
        finding = findings_fixture[0]

        mute_rule = MuteRule.objects.create(
            tenant_id=tenant.id,
            name="Test Mute Rule",
            reason="Testing mute functionality",
            enabled=True,
            created_by=test_user,
            finding_uids=[finding.uid],
        )

        return mute_rule

    @pytest.fixture(scope="function")
    def mute_rule_multiple_findings(self, scans_fixture, test_user):
        """
        Create multiple unmuted findings and a mute rule targeting all of them.
        """
        scan = scans_fixture[0]
        tenant_id = scan.tenant_id

        # Create 5 unmuted findings
        finding_uids = []
        for i in range(5):
            finding = Finding.objects.create(
                tenant_id=tenant_id,
                uid=f"test_finding_uid_mute_{i}",
                scan=scan,
                status=Status.FAIL,
                status_extended=f"Test status {i}",
                impact=Severity.high,
                severity=Severity.high,
                raw_result={
                    "status": Status.FAIL,
                    "impact": Severity.high,
                    "severity": Severity.high,
                },
                check_id=f"test_check_id_{i}",
                check_metadata={
                    "CheckId": f"test_check_id_{i}",
                    "Description": f"Test description {i}",
                },
                muted=False,
            )
            finding_uids.append(finding.uid)

        # Create mute rule targeting all findings
        mute_rule = MuteRule.objects.create(
            tenant_id=tenant_id,
            name="Test Multiple Findings Mute Rule",
            reason="Testing batch muting",
            enabled=True,
            created_by=test_user,
            finding_uids=finding_uids,
        )

        return mute_rule, finding_uids

    @pytest.fixture(scope="function")
    def mute_rule_already_muted(self, findings_fixture, test_user):
        """
        Create a mute rule that targets an already-muted finding.
        """
        tenant_id = findings_fixture[1].tenant_id
        already_muted_finding = findings_fixture[1]

        mute_rule = MuteRule.objects.create(
            tenant_id=tenant_id,
            name="Test Already Muted Rule",
            reason="Testing already muted findings",
            enabled=True,
            created_by=test_user,
            finding_uids=[already_muted_finding.uid],
        )

        return mute_rule

    @pytest.fixture(scope="function")
    def mute_rule_mixed_findings(self, scans_fixture, test_user):
        """
        Create a mute rule with a mix of muted and unmuted findings.
        """
        scan = scans_fixture[0]
        tenant_id = scan.tenant_id

        # Create 3 unmuted findings
        unmuted_uids = []
        for i in range(3):
            finding = Finding.objects.create(
                tenant_id=tenant_id,
                uid=f"unmuted_finding_{i}",
                scan=scan,
                status=Status.FAIL,
                status_extended=f"Unmuted status {i}",
                impact=Severity.medium,
                severity=Severity.medium,
                raw_result={
                    "status": Status.FAIL,
                    "impact": Severity.medium,
                    "severity": Severity.medium,
                },
                check_id=f"unmuted_check_{i}",
                check_metadata={
                    "CheckId": f"unmuted_check_{i}",
                    "Description": f"Unmuted description {i}",
                },
                muted=False,
            )
            unmuted_uids.append(finding.uid)

        # Create 2 already muted findings
        muted_uids = []
        for i in range(2):
            finding = Finding.objects.create(
                tenant_id=tenant_id,
                uid=f"muted_finding_{i}",
                scan=scan,
                status=Status.FAIL,
                status_extended=f"Muted status {i}",
                impact=Severity.low,
                severity=Severity.low,
                raw_result={
                    "status": Status.FAIL,
                    "impact": Severity.low,
                    "severity": Severity.low,
                },
                check_id=f"muted_check_{i}",
                check_metadata={
                    "CheckId": f"muted_check_{i}",
                    "Description": f"Muted description {i}",
                },
                muted=True,
                muted_at=datetime.now(timezone.utc),
                muted_reason="Already muted",
            )
            muted_uids.append(finding.uid)

        # Create mute rule targeting all findings
        all_uids = unmuted_uids + muted_uids
        mute_rule = MuteRule.objects.create(
            tenant_id=tenant_id,
            name="Test Mixed Findings Rule",
            reason="Testing mixed muted/unmuted findings",
            enabled=True,
            created_by=test_user,
            finding_uids=all_uids,
        )

        return mute_rule, unmuted_uids, muted_uids

    @pytest.fixture(scope="function")
    def mute_rule_batch_test(self, scans_fixture, test_user):
        """
        Create enough findings to test batch processing (>1000 for default batch size).
        """
        scan = scans_fixture[0]
        tenant_id = scan.tenant_id

        # Create 1500 findings to exceed default batch size of 1000
        finding_uids = []
        for i in range(1500):
            finding = Finding.objects.create(
                tenant_id=tenant_id,
                uid=f"batch_test_finding_{i}",
                scan=scan,
                status=Status.FAIL,
                status_extended=f"Batch test status {i}",
                impact=Severity.critical,
                severity=Severity.critical,
                raw_result={
                    "status": Status.FAIL,
                    "impact": Severity.critical,
                    "severity": Severity.critical,
                },
                check_id=f"batch_test_check_{i}",
                check_metadata={
                    "CheckId": f"batch_test_check_{i}",
                    "Description": f"Batch test description {i}",
                },
                muted=False,
            )
            finding_uids.append(finding.uid)

        # Create mute rule targeting all findings
        mute_rule = MuteRule.objects.create(
            tenant_id=tenant_id,
            name="Test Batch Processing Rule",
            reason="Testing batch processing functionality",
            enabled=True,
            created_by=test_user,
            finding_uids=finding_uids,
        )

        return mute_rule, finding_uids

    def test_mute_historical_findings_single_finding(
        self, mute_rule_with_findings, findings_fixture
    ):
        """
        Test muting a single historical finding.
        """
        mute_rule = mute_rule_with_findings
        tenant_id = str(mute_rule.tenant_id)
        finding = findings_fixture[0]

        # Ensure the finding is not muted before execution
        finding.refresh_from_db()
        assert finding.muted is False
        assert finding.muted_at is None
        assert finding.muted_reason is None

        # Execute the muting function
        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify return value
        assert result["findings_muted"] == 1
        assert result["rule_id"] == str(mute_rule.id)

        # Verify the finding was muted
        finding.refresh_from_db()
        assert finding.muted is True
        assert finding.muted_at == mute_rule.inserted_at
        assert finding.muted_reason == mute_rule.reason

    def test_mute_historical_findings_multiple_findings(
        self, mute_rule_multiple_findings
    ):
        """
        Test muting multiple historical findings.
        """
        mute_rule, finding_uids = mute_rule_multiple_findings
        tenant_id = str(mute_rule.tenant_id)

        # Verify all findings are unmuted
        findings = Finding.objects.filter(tenant_id=tenant_id, uid__in=finding_uids)
        assert findings.count() == 5
        for finding in findings:
            assert finding.muted is False

        # Execute the muting function
        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify return value
        assert result["findings_muted"] == 5
        assert result["rule_id"] == str(mute_rule.id)

        # Verify all findings were muted
        findings = Finding.objects.filter(tenant_id=tenant_id, uid__in=finding_uids)
        for finding in findings:
            assert finding.muted is True
            assert finding.muted_at == mute_rule.inserted_at
            assert finding.muted_reason == mute_rule.reason

    def test_mute_historical_findings_already_muted(
        self, mute_rule_already_muted, findings_fixture
    ):
        """
        Test that already-muted findings are not counted or updated.
        """
        mute_rule = mute_rule_already_muted
        tenant_id = str(mute_rule.tenant_id)
        finding = findings_fixture[1]

        # Verify the finding is already muted
        finding.refresh_from_db()
        assert finding.muted is True
        original_muted_at = finding.muted_at
        original_muted_reason = finding.muted_reason

        # Execute the muting function
        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify no findings were muted
        assert result["findings_muted"] == 0
        assert result["rule_id"] == str(mute_rule.id)

        # Verify the finding's mute status did not change
        finding.refresh_from_db()
        assert finding.muted is True
        assert finding.muted_at == original_muted_at
        assert finding.muted_reason == original_muted_reason

    def test_mute_historical_findings_mixed_status(self, mute_rule_mixed_findings):
        """
        Test muting when some findings are already muted and others are not.
        """
        mute_rule, unmuted_uids, muted_uids = mute_rule_mixed_findings
        tenant_id = str(mute_rule.tenant_id)

        # Execute the muting function
        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify only unmuted findings were counted
        assert result["findings_muted"] == 3
        assert result["rule_id"] == str(mute_rule.id)

        # Verify unmuted findings are now muted
        unmuted_findings = Finding.objects.filter(
            tenant_id=tenant_id, uid__in=unmuted_uids
        )
        for finding in unmuted_findings:
            assert finding.muted is True
            assert finding.muted_at == mute_rule.inserted_at
            assert finding.muted_reason == mute_rule.reason

        # Verify already-muted findings remained unchanged
        already_muted_findings = Finding.objects.filter(
            tenant_id=tenant_id, uid__in=muted_uids
        )
        for finding in already_muted_findings:
            assert finding.muted is True
            assert finding.muted_reason == "Already muted"

    def test_mute_historical_findings_nonexistent_rule(self, tenants_fixture):
        """
        Test that a nonexistent mute rule raises ObjectDoesNotExist.
        """
        tenant_id = str(tenants_fixture[0].id)
        nonexistent_rule_id = str(uuid4())

        with pytest.raises(ObjectDoesNotExist):
            mute_historical_findings(tenant_id, nonexistent_rule_id)

    def test_mute_historical_findings_no_matching_findings(
        self, tenants_fixture, test_user
    ):
        """
        Test muting when no findings match the rule's UIDs.
        """
        tenant_id = str(tenants_fixture[0].id)

        # Create a mute rule with non-existent finding UIDs
        mute_rule = MuteRule.objects.create(
            tenant_id=tenant_id,
            name="Test No Match Rule",
            reason="Testing no matching findings",
            enabled=True,
            created_by=test_user,
            finding_uids=[
                "nonexistent_uid_1",
                "nonexistent_uid_2",
                "nonexistent_uid_3",
            ],
        )

        # Execute the muting function
        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify no findings were muted
        assert result["findings_muted"] == 0
        assert result["rule_id"] == str(mute_rule.id)

    def test_mute_historical_findings_batch_processing(self, mute_rule_batch_test):
        """
        Test that large numbers of findings are processed in batches correctly.
        """
        mute_rule, finding_uids = mute_rule_batch_test
        tenant_id = str(mute_rule.tenant_id)

        # Verify all findings exist and are unmuted
        findings = Finding.objects.filter(tenant_id=tenant_id, uid__in=finding_uids)
        assert findings.count() == 1500
        for finding in findings:
            assert finding.muted is False

        # Execute the muting function
        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify return value
        assert result["findings_muted"] == 1500
        assert result["rule_id"] == str(mute_rule.id)

        # Verify all findings were muted
        findings = Finding.objects.filter(tenant_id=tenant_id, uid__in=finding_uids)
        for finding in findings:
            assert finding.muted is True
            assert finding.muted_at == mute_rule.inserted_at
            assert finding.muted_reason == mute_rule.reason

    def test_mute_historical_findings_preserves_muted_at_timestamp(
        self, mute_rule_with_findings, findings_fixture
    ):
        """
        Test that muted_at is set to the rule's inserted_at, not the current time.
        """
        mute_rule = mute_rule_with_findings
        tenant_id = str(mute_rule.tenant_id)
        finding = findings_fixture[0]

        # Execute the muting function
        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify the finding was muted
        assert result["findings_muted"] == 1

        # Verify muted_at matches the rule's inserted_at timestamp
        finding.refresh_from_db()
        assert finding.muted_at == mute_rule.inserted_at
        assert finding.muted_at is not None

    def test_mute_historical_findings_partial_match(self, scans_fixture, test_user):
        """
        Test muting when only some of the rule's UIDs exist as findings.
        """
        scan = scans_fixture[0]
        tenant_id = str(scan.tenant_id)

        # Create 3 findings
        existing_uids = []
        for i in range(3):
            finding = Finding.objects.create(
                tenant_id=tenant_id,
                uid=f"partial_match_finding_{i}",
                scan=scan,
                status=Status.FAIL,
                status_extended=f"Partial match status {i}",
                impact=Severity.high,
                severity=Severity.high,
                raw_result={
                    "status": Status.FAIL,
                    "impact": Severity.high,
                    "severity": Severity.high,
                },
                check_id=f"partial_match_check_{i}",
                check_metadata={
                    "CheckId": f"partial_match_check_{i}",
                    "Description": f"Partial match description {i}",
                },
                muted=False,
            )
            existing_uids.append(finding.uid)

        # Create a mute rule with both existing and non-existing UIDs
        all_uids = existing_uids + [
            "nonexistent_uid_1",
            "nonexistent_uid_2",
        ]
        mute_rule = MuteRule.objects.create(
            tenant_id=tenant_id,
            name="Test Partial Match Rule",
            reason="Testing partial matching",
            enabled=True,
            created_by=test_user,
            finding_uids=all_uids,
        )

        # Execute the muting function
        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify only existing findings were muted
        assert result["findings_muted"] == 3
        assert result["rule_id"] == str(mute_rule.id)

        # Verify the existing findings were muted
        findings = Finding.objects.filter(tenant_id=tenant_id, uid__in=existing_uids)
        assert findings.count() == 3
        for finding in findings:
            assert finding.muted is True
            assert finding.muted_at == mute_rule.inserted_at
            assert finding.muted_reason == mute_rule.reason

    def test_mute_historical_findings_empty_uids(self, tenants_fixture, test_user):
        """
        Test muting when the rule has an empty finding_uids array.
        """
        tenant_id = str(tenants_fixture[0].id)

        # Create a mute rule with empty finding_uids
        mute_rule = MuteRule.objects.create(
            tenant_id=tenant_id,
            name="Test Empty UIDs Rule",
            reason="Testing empty UIDs",
            enabled=True,
            created_by=test_user,
            finding_uids=[],
        )

        # Execute the muting function
        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify no findings were muted
        assert result["findings_muted"] == 0
        assert result["rule_id"] == str(mute_rule.id)

    def test_mute_historical_findings_return_format(self, mute_rule_with_findings):
        """
        Test that the return value has the correct format and fields.
        """
        mute_rule = mute_rule_with_findings
        tenant_id = str(mute_rule.tenant_id)

        result = mute_historical_findings(tenant_id, str(mute_rule.id))

        # Verify return value structure
        assert isinstance(result, dict)
        assert "findings_muted" in result
        assert "rule_id" in result
        assert isinstance(result["findings_muted"], int)
        assert isinstance(result["rule_id"], str)
        assert result["rule_id"] == str(mute_rule.id)
