import re
from types import SimpleNamespace

from prowler.lib.outputs.compliance.asd_essential_eight.asd_essential_eight import (
    get_asd_essential_eight_table,
)


def _make_finding(check_id, status="PASS", muted=False):
    return SimpleNamespace(
        check_metadata=SimpleNamespace(CheckID=check_id),
        status=status,
        muted=muted,
    )


def _make_compliance(provider, sections, framework="ASD-Essential-Eight"):
    """Build a per-check compliance covering the given sections."""
    return SimpleNamespace(
        Framework=framework,
        Provider=provider,
        Requirements=[
            SimpleNamespace(Attributes=[SimpleNamespace(Section=section)])
            for section in sections
        ],
    )


class TestASDEssentialEightTable:
    """Test cases verifying multi-section counting and provider-column attribution for the ASD Essential Eight compliance table."""

    def test_multi_section_fail_not_undercounted(self, capsys, tmp_path):
        """A single FAIL check mapped to several sections must show FAIL(1) in
        every section, not just the first one seen."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[_make_compliance("aws", ["IAM", "Logging"])]
            ),
            "check_b": SimpleNamespace(Compliance=[_make_compliance("aws", ["IAM"])]),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        get_asd_essential_eight_table(
            findings,
            bulk_metadata,
            "asd_essential_eight_aws",
            "output",
            str(tmp_path),
            False,
        )

        captured = capsys.readouterr()
        # Both IAM and Logging must report FAIL(1); before the fix Logging was
        # undercounted because the per-section count was gated by the global
        # dedup list.
        assert captured.out.count("FAIL(1)") == 2

    def test_multi_section_muted_not_undercounted(self, capsys, tmp_path):
        """A single MUTED check mapped to several sections must increase the
        per-section Muted count in every section, not only the first one."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[_make_compliance("aws", ["IAM", "Logging"])]
            ),
            "check_b": SimpleNamespace(Compliance=[_make_compliance("aws", ["IAM"])]),
        }
        findings = [
            _make_finding("check_a", "FAIL", muted=True),
            # A real FAIL is needed so the results table is rendered at all.
            _make_finding("check_b", "FAIL"),
        ]

        get_asd_essential_eight_table(
            findings,
            bulk_metadata,
            "asd_essential_eight_aws",
            "output",
            str(tmp_path),
            False,
        )

        captured = capsys.readouterr()
        plain = re.sub(r"\x1b\[[0-9;]*m", "", captured.out)
        # The muted check belongs to both IAM and Logging, so the Muted column
        # must read 1 in both rows.
        muted_cells = re.findall(r"│\s*1\s*│\s*$", plain, flags=re.MULTILINE)
        assert len(muted_cells) == 2

    def test_provider_column_not_leaked_from_other_framework(self, capsys, tmp_path):
        """The Provider column must come from the matched ASD-Essential-Eight
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

        get_asd_essential_eight_table(
            findings,
            bulk_metadata,
            "asd_essential_eight_aws",
            "output",
            str(tmp_path),
            False,
        )

        captured = capsys.readouterr()
        assert "aws" in captured.out
        # The provider of the unrelated trailing framework must NOT leak into
        # the rendered table.
        assert "leaked_provider" not in captured.out
