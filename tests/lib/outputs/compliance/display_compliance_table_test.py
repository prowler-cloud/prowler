"""Tests for display_compliance_table dispatch logic.

Validates that each compliance framework name is routed to the correct
table renderer via startswith matching, and that the universal early-return
takes precedence when applicable.
"""

from unittest.mock import patch

import pytest

from prowler.lib.check.compliance_models import (
    ComplianceFramework,
    OutputsConfig,
    TableConfig,
    UniversalComplianceRequirement,
)
from prowler.lib.outputs.compliance.compliance import display_compliance_table

MODULE = "prowler.lib.outputs.compliance.compliance"

# Common args shared by every call — the actual values don't matter
# because we mock the downstream renderers.
_COMMON = dict(
    findings=[],
    bulk_checks_metadata={},
    output_filename="out",
    output_directory="/tmp",
    compliance_overview=False,
)


# ── Dispatch to legacy table renderers ───────────────────────────────


class TestDispatchStartswith:
    """Each framework prefix must route to exactly one renderer."""

    @pytest.mark.parametrize(
        "framework_name",
        [
            "cis_1.4_aws",
            "cis_2.0_azure",
            "cis_3.0_gcp",
            "cis_6.0_m365",
            "cis_1.10_kubernetes",
        ],
    )
    @patch(f"{MODULE}.get_cis_table")
    def test_cis_dispatch(self, mock_fn, framework_name):
        display_compliance_table(compliance_framework=framework_name, **_COMMON)
        mock_fn.assert_called_once()

    @pytest.mark.parametrize(
        "framework_name",
        ["ens_rd2022_aws", "ens_rd2022_azure", "ens_rd2022_gcp"],
    )
    @patch(f"{MODULE}.get_ens_table")
    def test_ens_dispatch(self, mock_fn, framework_name):
        display_compliance_table(compliance_framework=framework_name, **_COMMON)
        mock_fn.assert_called_once()

    @pytest.mark.parametrize(
        "framework_name",
        ["mitre_attack_aws", "mitre_attack_azure", "mitre_attack_gcp"],
    )
    @patch(f"{MODULE}.get_mitre_attack_table")
    def test_mitre_dispatch(self, mock_fn, framework_name):
        display_compliance_table(compliance_framework=framework_name, **_COMMON)
        mock_fn.assert_called_once()

    @pytest.mark.parametrize(
        "framework_name",
        ["kisa_isms_p_2023_aws", "kisa_isms_p_2023_korean_aws"],
    )
    @patch(f"{MODULE}.get_kisa_ismsp_table")
    def test_kisa_dispatch(self, mock_fn, framework_name):
        display_compliance_table(compliance_framework=framework_name, **_COMMON)
        mock_fn.assert_called_once()

    @pytest.mark.parametrize(
        "framework_name",
        [
            "prowler_threatscore_aws",
            "prowler_threatscore_azure",
            "prowler_threatscore_gcp",
            "prowler_threatscore_kubernetes",
            "prowler_threatscore_m365",
            "prowler_threatscore_alibabacloud",
        ],
    )
    @patch(f"{MODULE}.get_prowler_threatscore_table")
    def test_threatscore_dispatch(self, mock_fn, framework_name):
        display_compliance_table(compliance_framework=framework_name, **_COMMON)
        mock_fn.assert_called_once()

    @pytest.mark.parametrize(
        "framework_name",
        [
            "csa_ccm_4.0_aws",
            "csa_ccm_4.0_azure",
            "csa_ccm_4.0_gcp",
            "csa_ccm_4.0_oraclecloud",
            "csa_ccm_4.0_alibabacloud",
        ],
    )
    @patch(f"{MODULE}.get_csa_table")
    def test_csa_dispatch(self, mock_fn, framework_name):
        display_compliance_table(compliance_framework=framework_name, **_COMMON)
        mock_fn.assert_called_once()

    @pytest.mark.parametrize(
        "framework_name",
        ["c5_aws", "c5_azure", "c5_gcp"],
    )
    @patch(f"{MODULE}.get_c5_table")
    def test_c5_dispatch(self, mock_fn, framework_name):
        display_compliance_table(compliance_framework=framework_name, **_COMMON)
        mock_fn.assert_called_once()

    @pytest.mark.parametrize(
        "framework_name",
        [
            "soc2_aws",
            "hipaa_aws",
            "gdpr_aws",
            "nist_800_53_revision_4_aws",
            "pci_3.2.1_aws",
            "iso27001_2013_aws",
            "aws_well_architected_framework_security_pillar_aws",
            "fedramp_low_revision_4_aws",
            "cisa_aws",
        ],
    )
    @patch(f"{MODULE}.get_generic_compliance_table")
    def test_generic_dispatch(self, mock_fn, framework_name):
        display_compliance_table(compliance_framework=framework_name, **_COMMON)
        mock_fn.assert_called_once()


# ── No false matches (the old `in` bug) ─────────────────────────────


class TestNoFalseSubstringMatches:
    """Frameworks that previously could false-match with `in` must NOT
    be routed to the wrong renderer now that we use startswith."""

    @patch(f"{MODULE}.get_ens_table")
    @patch(f"{MODULE}.get_generic_compliance_table")
    def test_cisa_does_not_match_cis(self, mock_generic, mock_cis):
        """'cisa_aws' must NOT match startswith('cis_')."""
        display_compliance_table(compliance_framework="cisa_aws", **_COMMON)
        mock_generic.assert_called_once()
        mock_cis.assert_not_called()

    @patch(f"{MODULE}.get_prowler_threatscore_table")
    @patch(f"{MODULE}.get_generic_compliance_table")
    def test_threatscore_prefix_not_partial(self, mock_generic, mock_ts):
        """A hypothetical 'threatscore_custom_aws' must NOT match
        startswith('prowler_threatscore_')."""
        display_compliance_table(
            compliance_framework="threatscore_custom_aws", **_COMMON
        )
        mock_generic.assert_called_once()
        mock_ts.assert_not_called()

    @patch(f"{MODULE}.get_ens_table")
    @patch(f"{MODULE}.get_prowler_threatscore_table")
    def test_prowler_threatscore_does_not_match_ens(self, mock_ts, mock_ens):
        """'prowler_threatscore_aws' must hit threatscore, never ens."""
        display_compliance_table(
            compliance_framework="prowler_threatscore_aws", **_COMMON
        )
        mock_ts.assert_called_once()
        mock_ens.assert_not_called()


# ── Universal early-return ───────────────────────────────────────────


class TestUniversalEarlyReturn:
    """The universal path must take precedence over the elif chain."""

    @staticmethod
    def _make_fw():
        return ComplianceFramework(
            framework="CIS",
            name="CIS",
            provider="AWS",
            version="5.0",
            description="d",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="d",
                    attributes={},
                    checks={"aws": ["check_a"]},
                ),
            ],
            outputs=OutputsConfig(table_config=TableConfig(group_by="_default")),
        )

    @patch(f"{MODULE}.get_universal_table")
    @patch(f"{MODULE}.get_cis_table")
    def test_universal_takes_precedence_over_cis(self, mock_cis, mock_universal):
        """A CIS framework in universal_frameworks with TableConfig must
        use the universal renderer, not get_cis_table."""
        fw = self._make_fw()
        display_compliance_table(
            compliance_framework="cis_5.0_aws",
            universal_frameworks={"cis_5.0_aws": fw},
            **_COMMON,
        )
        mock_universal.assert_called_once()
        mock_cis.assert_not_called()

    @patch(f"{MODULE}.get_universal_table")
    @patch(f"{MODULE}.get_cis_table")
    def test_falls_through_without_table_config(self, mock_cis, mock_universal):
        """If the universal framework has no TableConfig, fall through
        to the legacy elif chain."""
        fw = self._make_fw()
        fw.outputs = None
        display_compliance_table(
            compliance_framework="cis_5.0_aws",
            universal_frameworks={"cis_5.0_aws": fw},
            **_COMMON,
        )
        mock_cis.assert_called_once()
        mock_universal.assert_not_called()

    @patch(f"{MODULE}.get_universal_table")
    @patch(f"{MODULE}.get_generic_compliance_table")
    def test_falls_through_when_not_in_universal_dict(
        self, mock_generic, mock_universal
    ):
        """If universal_frameworks is empty, fall through to legacy."""
        display_compliance_table(
            compliance_framework="soc2_aws",
            universal_frameworks={},
            **_COMMON,
        )
        mock_generic.assert_called_once()
        mock_universal.assert_not_called()
