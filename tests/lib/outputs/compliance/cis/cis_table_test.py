import re
from types import SimpleNamespace

from prowler.lib.outputs.compliance.cis.cis import get_cis_table


def _strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _make_finding(check_id, status="PASS", muted=False):
    return SimpleNamespace(
        check_metadata=SimpleNamespace(CheckID=check_id),
        status=status,
        muted=muted,
    )


def _attr(section, profile="Level 1"):
    return SimpleNamespace(Section=section, Profile=profile)


def _make_compliance(provider, attributes, version="1.4", framework="CIS"):
    """Build a per-check CIS compliance with the given (section, profile) attrs."""
    return SimpleNamespace(
        Framework=framework,
        Version=version,
        Provider=provider,
        Requirements=[SimpleNamespace(Attributes=attributes)],
    )


class TestCISTable:
    """Verify multi-section counting and provider-column attribution for the CIS compliance table."""

    def test_muted_multi_section_not_undercounted(self, capsys, tmp_path):
        """A single MUTED finding mapped to several sections must increment the
        per-section Muted column for every section, not only the first seen.

        CIS counts FAIL/PASS through Level 1/Level 2 buckets, so only the Muted
        per-section count was affected by the undercount bug.
        """
        bulk_metadata = {
            # check_a is muted and belongs to two sections at once.
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", [_attr("1 IAM"), _attr("2 Logging")])
                ]
            ),
            # A real (non-muted) finding so the table is rendered.
            "check_b": SimpleNamespace(
                Compliance=[_make_compliance("aws", [_attr("1 IAM")])]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL", muted=True),
            _make_finding("check_b", "PASS"),
        ]

        get_cis_table(
            findings,
            bulk_metadata,
            "cis_1.4_aws",
            "output",
            str(tmp_path),
            False,
        )

        captured = capsys.readouterr()
        plain = _strip_ansi(captured.out)
        # Both section rows must carry a Muted count of 1 in their last cell.
        # Before the fix only the first section seen got incremented.
        muted_one_rows = re.findall(r"│\s*1\s*│\s*$", plain, flags=re.MULTILINE)
        assert len(muted_one_rows) == 2

    def test_provider_column_not_leaked_from_other_framework(self, capsys, tmp_path):
        """The Provider column must come from the matched CIS compliance, not
        from a different framework that trails it in the compliance list."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", [_attr("1 IAM")]),
                    _make_compliance(
                        "gcp", [_attr("Other")], framework="OtherFramework"
                    ),
                ]
            ),
            "check_b": SimpleNamespace(
                Compliance=[
                    _make_compliance("aws", [_attr("1 IAM")]),
                    _make_compliance(
                        "gcp", [_attr("Other")], framework="OtherFramework"
                    ),
                ]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        get_cis_table(
            findings,
            bulk_metadata,
            "cis_1.4_aws",
            "output",
            str(tmp_path),
            False,
        )

        captured = capsys.readouterr()
        assert "aws" in captured.out
        # The trailing unrelated framework's provider must not leak in.
        assert "gcp" not in captured.out
