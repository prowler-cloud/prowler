import re
from types import SimpleNamespace

from prowler.lib.outputs.compliance.mitre_attack.mitre_attack import (
    get_mitre_attack_table,
)

# The generator matches a compliance when "MITRE-ATTACK" is in its Framework and
# its Version is contained in the compliance_framework argument.
COMPLIANCE_FRAMEWORK = "mitre_attack_aws"


def _make_finding(check_id, status="PASS", muted=False):
    return SimpleNamespace(
        check_metadata=SimpleNamespace(CheckID=check_id),
        status=status,
        muted=muted,
    )


def _make_compliance(
    provider, tactics, framework="MITRE-ATTACK", version="mitre_attack"
):
    """Build a per-check compliance covering the given tactics."""
    return SimpleNamespace(
        Framework=framework,
        Version=version,
        Provider=provider,
        Requirements=[SimpleNamespace(Tactics=tactics)],
    )


class TestMitreAttackTable:
    def test_multi_tactic_fail_not_undercounted(self, capsys):
        """A single FAIL check mapped to several tactics must show FAIL(1) in
        every tactic, not just the first one seen."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[_make_compliance("aws", ["Persistence", "Execution"])]
            ),
            "check_b": SimpleNamespace(
                Compliance=[_make_compliance("aws", ["Persistence"])]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        get_mitre_attack_table(
            findings,
            bulk_metadata,
            COMPLIANCE_FRAMEWORK,
            "output",
            "/tmp",
            False,
        )

        captured = capsys.readouterr()
        # Both Persistence and Execution must report FAIL(1); before the fix
        # Execution was undercounted because the per-tactic count was gated by
        # the global dedup list.
        assert captured.out.count("FAIL(1)") == 2

    def test_multi_tactic_muted_not_undercounted(self, capsys):
        """A single MUTED check mapped to several tactics must increase the
        per-tactic Muted count in every tactic, not only the first one."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[_make_compliance("aws", ["Persistence", "Execution"])]
            ),
            "check_b": SimpleNamespace(
                Compliance=[_make_compliance("aws", ["Persistence"])]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL", muted=True),
            # A second finding is needed so the table is rendered at all.
            _make_finding("check_b", "FAIL"),
        ]

        get_mitre_attack_table(
            findings,
            bulk_metadata,
            COMPLIANCE_FRAMEWORK,
            "output",
            "/tmp",
            False,
        )

        captured = capsys.readouterr()
        plain = re.sub(r"\x1b\[[0-9;]*m", "", captured.out)
        # The muted check belongs to both Persistence and Execution, so the
        # Muted column must read 1 in both rows.
        muted_cells = re.findall(r"│\s*1\s*│\s*$", plain, flags=re.MULTILINE)
        assert len(muted_cells) == 2

    def test_provider_column_not_leaked_from_other_framework(self, capsys):
        """The Provider column must come from the matched MITRE-ATTACK
        compliance, never from a different framework that happens to be the last
        entry in the check's compliance list."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", ["Persistence"]),
                    _make_compliance(
                        "leaked_provider", ["Other"], framework="OtherFramework"
                    ),
                ]
            ),
            "check_b": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", ["Persistence"]),
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

        get_mitre_attack_table(
            findings,
            bulk_metadata,
            COMPLIANCE_FRAMEWORK,
            "output",
            "/tmp",
            False,
        )

        captured = capsys.readouterr()
        assert "aws" in captured.out
        # The provider of the unrelated trailing framework must NOT leak into
        # the rendered table.
        assert "leaked_provider" not in captured.out
