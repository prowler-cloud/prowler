import re
from types import SimpleNamespace
from unittest import mock

from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore import (
    get_prowler_threatscore_table,
)

# Patch target for the Compliance.get_bulk lookup used to render pillars without
# findings; the tests don't exercise that path so it returns nothing.
COMPLIANCE_PATH = (
    "prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore.Compliance"
)


def _make_finding(check_id, status="PASS", muted=False):
    return SimpleNamespace(
        check_metadata=SimpleNamespace(CheckID=check_id),
        status=status,
        muted=muted,
    )


def _make_compliance(provider, pillars, framework="ProwlerThreatScore"):
    """Build a per-check compliance covering the given pillars (Section)."""
    return SimpleNamespace(
        Framework=framework,
        Provider=provider,
        Requirements=[
            SimpleNamespace(
                Attributes=[SimpleNamespace(Section=pillar, LevelOfRisk=5, Weight=100)]
            )
            for pillar in pillars
        ],
    )


class TestProwlerThreatScoreTable:
    """Verify multi-section counting and provider-column attribution for the compliance table."""

    def test_multi_pillar_fail_not_undercounted(self, capsys, tmp_path):
        """A single FAIL check mapped to several pillars must show FAIL(1) in
        every pillar, not just the first one seen."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[_make_compliance("aws", ["IAM", "Encryption"])]
            ),
            "check_b": SimpleNamespace(Compliance=[_make_compliance("aws", ["IAM"])]),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        with mock.patch(COMPLIANCE_PATH) as compliance_mock:
            compliance_mock.get_bulk.return_value = {}
            get_prowler_threatscore_table(
                findings,
                bulk_metadata,
                "prowler_threatscore_aws",
                "output",
                str(tmp_path),
                False,
            )

        captured = capsys.readouterr()
        # Both IAM and Encryption must report FAIL(1); before the fix Encryption
        # was undercounted because the per-pillar count was gated by the global
        # dedup list.
        assert captured.out.count("FAIL(1)") == 2

    def test_multi_pillar_muted_not_undercounted(self, capsys, tmp_path):
        """A single MUTED check mapped to several pillars must increase the
        per-pillar Muted count in every pillar, not only the first one."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[_make_compliance("aws", ["IAM", "Encryption"])]
            ),
            "check_b": SimpleNamespace(Compliance=[_make_compliance("aws", ["IAM"])]),
        }
        findings = [
            _make_finding("check_a", "FAIL", muted=True),
            # A real FAIL is needed so the results table is rendered at all.
            _make_finding("check_b", "FAIL"),
        ]

        with mock.patch(COMPLIANCE_PATH) as compliance_mock:
            compliance_mock.get_bulk.return_value = {}
            get_prowler_threatscore_table(
                findings,
                bulk_metadata,
                "prowler_threatscore_aws",
                "output",
                str(tmp_path),
                False,
            )

        captured = capsys.readouterr()
        plain = re.sub(r"\x1b\[[0-9;]*m", "", captured.out)
        # The muted check belongs to both IAM and Encryption, so the Muted
        # column must read 1 in both rows.
        muted_cells = re.findall(r"│\s*1\s*│\s*$", plain, flags=re.MULTILINE)
        assert len(muted_cells) == 2

    def test_provider_column_not_leaked_from_other_framework(self, capsys, tmp_path):
        """The Provider column must come from the matched ProwlerThreatScore
        compliance, never from a different framework that happens to be the last
        entry in the check's compliance list."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", ["IAM"]),
                    _make_compliance(
                        "leaked_provider", ["Other"], framework="OtherFramework"
                    ),
                ]
            ),
            "check_b": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", ["IAM"]),
                    _make_compliance(
                        "leaked_provider", ["Other"], framework="OtherFramework"
                    ),
                ]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        with mock.patch(COMPLIANCE_PATH) as compliance_mock:
            compliance_mock.get_bulk.return_value = {}
            get_prowler_threatscore_table(
                findings,
                bulk_metadata,
                "prowler_threatscore_aws",
                "output",
                str(tmp_path),
                False,
            )

        captured = capsys.readouterr()
        assert "aws" in captured.out
        # The provider of the unrelated trailing framework must NOT leak into
        # the rendered table.
        assert "leaked_provider" not in captured.out
