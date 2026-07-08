from types import SimpleNamespace
from unittest.mock import patch

from prowler.lib.outputs.compliance.okta_idaas_stig.okta_idaas_stig import (
    get_okta_idaas_stig_table,
)


def _make_finding(check_id, status="PASS", muted=False):
    return SimpleNamespace(
        check_metadata=SimpleNamespace(CheckID=check_id),
        check_id=check_id,
        status=status,
        muted=muted,
    )


def _make_compliance(
    provider,
    sections,
    framework="Okta-IDaaS-STIG",
    checks=None,
    config_requirements=None,
):
    """Build a per-check compliance covering the given sections.

    ``checks`` and ``config_requirements`` let a section's requirement declare
    the checks it owns and the config constraints that gate it, so the table's
    config-status override can be exercised.
    """
    return SimpleNamespace(
        Framework=framework,
        Provider=provider,
        Requirements=[
            SimpleNamespace(
                Id=f"REQ-{section}",
                Checks=list(checks or []),
                ConfigRequirements=list(config_requirements or []),
                Attributes=[SimpleNamespace(Section=section)],
            )
            for section in sections
        ],
    )


class TestOktaIDaaSSTIGTable:
    """Test cases for Okta IDaaS STIG compliance table rendering."""

    def test_multi_section_fail_not_undercounted(self, capsys, tmp_path):
        """A single FAIL check mapped to several sections must show FAIL(1) in
        every section, not just the first one seen."""
        bulk_metadata = {
            # check_a belongs to two sections at once.
            "check_a": SimpleNamespace(
                Compliance=[_make_compliance("okta", ["IAM", "Logging"])]
            ),
            "check_b": SimpleNamespace(Compliance=[_make_compliance("okta", ["IAM"])]),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        get_okta_idaas_stig_table(
            findings,
            bulk_metadata,
            "okta_idaas_stig_1r2",
            "output",
            str(tmp_path),
            False,
        )

        captured = capsys.readouterr()
        # Both IAM and Logging must report FAIL(1); before the fix Logging
        # was undercounted and rendered as plain PASS.
        assert captured.out.count("FAIL(1)") == 2

    def test_multi_section_muted_not_undercounted(self, capsys, tmp_path):
        """A single MUTED check mapped to several sections must increase the
        per-section Muted count in every section, not only the first one."""
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[_make_compliance("okta", ["IAM", "Logging"])]
            ),
            "check_b": SimpleNamespace(Compliance=[_make_compliance("okta", ["IAM"])]),
        }
        findings = [
            _make_finding("check_a", "FAIL", muted=True),
            # A real FAIL is needed so the results table is rendered at all.
            _make_finding("check_b", "FAIL"),
        ]

        get_okta_idaas_stig_table(
            findings,
            bulk_metadata,
            "okta_idaas_stig_1r2",
            "output",
            str(tmp_path),
            False,
        )

        captured = capsys.readouterr()
        # The muted check belongs to both IAM and Logging, so the Muted column
        # must read 1 in both rows. Before the fix only the first section seen
        # was incremented, leaving the second at 0.
        # Strip ANSI color codes before counting the bare values per row.
        import re

        plain = re.sub(r"\x1b\[[0-9;]*m", "", captured.out)
        # Each section row ends with its Muted value in its own cell; both rows
        # must carry a Muted count of 1.
        muted_cells = re.findall(r"│\s*1\s*│\s*$", plain, flags=re.MULTILINE)
        assert len(muted_cells) == 2

    def test_provider_column_not_leaked_from_other_framework(self, capsys, tmp_path):
        """The Provider column must come from the matched Okta-IDaaS-STIG
        compliance, never from a different framework that happens to be the
        last entry in the check's compliance list."""
        # check_a maps to Okta-IDaaS-STIG (provider "okta") but its compliance
        # list ends with a *different* framework whose provider is "aws". With
        # the bug the leaked loop variable made the table render "aws".
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance("okta", ["IAM"]),
                    _make_compliance("aws", ["Other"], framework="OtherFramework"),
                ]
            ),
            "check_b": SimpleNamespace(
                Compliance=[
                    _make_compliance("okta", ["IAM"]),
                    _make_compliance("aws", ["Other"], framework="OtherFramework"),
                ]
            ),
        }
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
        ]

        get_okta_idaas_stig_table(
            findings,
            bulk_metadata,
            "okta_idaas_stig_1r2",
            "output",
            str(tmp_path),
            False,
        )

        captured = capsys.readouterr()
        assert "okta" in captured.out
        # The provider of the unrelated trailing framework must NOT leak into
        # the rendered table.
        assert "aws" not in captured.out

    def test_config_status_override_forces_fail(self, capsys, tmp_path):
        """A configurable check that PASSes but ran with a config too loose for
        its requirement must be forced to FAIL in the table, honouring the
        requirement's ConfigRequirements. Without the override check_a would be
        PASS and no results table would render at all."""
        constraint = {
            "Check": "check_a",
            "ConfigKey": "okta_max_session_idle_minutes",
            "Operator": "lte",
            "Value": 15,
        }
        bulk_metadata = {
            "check_a": SimpleNamespace(
                Compliance=[
                    _make_compliance(
                        "okta",
                        ["IAM"],
                        checks=["check_a"],
                        config_requirements=[constraint],
                    )
                ]
            ),
            "check_b": SimpleNamespace(
                Compliance=[_make_compliance("okta", ["Logging"])]
            ),
        }
        # Both checks PASS on their own; the scan applied a 30-minute idle
        # timeout, which is too loose for the 15-minute requirement.
        findings = [
            _make_finding("check_a", "PASS"),
            _make_finding("check_b", "PASS"),
        ]

        with (
            patch(
                "prowler.lib.outputs.compliance.okta_idaas_stig.okta_idaas_stig.get_scan_audit_config",
                return_value={"okta_max_session_idle_minutes": 30},
            ),
            patch(
                "prowler.lib.check.compliance_config_eval.get_scan_provider_type",
                return_value="okta",
            ),
        ):
            get_okta_idaas_stig_table(
                findings,
                bulk_metadata,
                "okta_idaas_stig_1r2",
                "output",
                str(tmp_path),
                False,
            )

        captured = capsys.readouterr()
        # check_a was forced to FAIL by the config override, so its section
        # (IAM) must report FAIL(1).
        assert "FAIL(1)" in captured.out
