"""Tests for process_universal_compliance_frameworks and --list-compliance fixes.

Validates that the pre-processing step:
 - generates both CSV and OCSF outputs for universal frameworks
 - always generates OCSF (no output-format gate)
 - skips frameworks without outputs or table_config
 - skips frameworks not in universal_frameworks
 - returns the set of processed names for removal from the legacy loop
 - works across different providers

Also validates that print_compliance_frameworks and print_compliance_requirements
work with universal ComplianceFramework objects (dict checks, None provider).
"""

import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from prowler.lib.check.check import (
    print_compliance_frameworks,
    print_compliance_requirements,
)
from prowler.lib.check.compliance_models import (
    AttributeMetadata,
    ComplianceFramework,
    OutputsConfig,
    TableConfig,
    UniversalComplianceRequirement,
)
from prowler.lib.outputs.compliance.compliance import (
    process_universal_compliance_frameworks,
)
from prowler.lib.outputs.compliance.universal.ocsf_compliance import (
    OCSFComplianceOutput,
)
from prowler.lib.outputs.compliance.universal.universal_output import (
    UniversalComplianceOutput,
)


@pytest.fixture(autouse=True)
def _create_compliance_dir(tmp_path):
    """Ensure the compliance/ subdirectory exists before each test."""
    os.makedirs(tmp_path / "compliance", exist_ok=True)


# ── Helpers ──────────────────────────────────────────────────────────


def _make_finding(check_id, status="PASS", provider="aws"):
    """Create a mock Finding with all fields needed by both output classes."""
    finding = SimpleNamespace()
    finding.provider = provider
    finding.account_uid = "123456789012"
    finding.account_name = "test-account"
    finding.account_email = ""
    finding.account_organization_uid = "org-123"
    finding.account_organization_name = "test-org"
    finding.account_tags = {"env": "test"}
    finding.region = "us-east-1"
    finding.status = status
    finding.status_extended = f"{check_id} is {status}"
    finding.resource_uid = f"arn:aws:iam::123456789012:{check_id}"
    finding.resource_name = check_id
    finding.resource_details = "some details"
    finding.resource_metadata = {}
    finding.resource_tags = {"Name": "test"}
    finding.partition = "aws"
    finding.muted = False
    finding.check_id = check_id
    finding.uid = "test-finding-uid"
    finding.timestamp = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    finding.prowler_version = "5.0.0"
    finding.compliance = {"TestFW-1.0": ["1.1"]}
    finding.metadata = SimpleNamespace(
        Provider=provider,
        CheckID=check_id,
        CheckTitle=f"Title for {check_id}",
        CheckType=["test-type"],
        Description=f"Description for {check_id}",
        Severity="medium",
        ServiceName="iam",
        ResourceType="aws-iam-role",
        Risk="test-risk",
        RelatedUrl="https://example.com",
        Remediation=SimpleNamespace(
            Recommendation=SimpleNamespace(Text="Fix it", Url="https://fix.com"),
        ),
        DependsOn=[],
        RelatedTo=[],
        Categories=["test"],
        Notes="",
        AdditionalURLs=[],
    )
    return finding


def _make_universal_framework(name="TestFW", version="1.0", with_table_config=True):
    """Build a ComplianceFramework with optional table_config."""
    reqs = [
        UniversalComplianceRequirement(
            id="1.1",
            description="Test requirement",
            attributes={"Section": "IAM"},
            checks={"aws": ["check_a"]},
        ),
    ]
    metadata = [AttributeMetadata(key="Section", type="str")]
    outputs = None
    if with_table_config:
        outputs = OutputsConfig(table_config=TableConfig(group_by="Section"))
    return ComplianceFramework(
        framework=name,
        name=f"{name} Framework",
        provider="AWS",
        version=version,
        description="Test framework",
        requirements=reqs,
        attributes_metadata=metadata,
        outputs=outputs,
    )


# ── Tests ────────────────────────────────────────────────────────────


class TestProcessUniversalComplianceFrameworks:
    """Core tests for the extracted pre-processing function."""

    def test_generates_csv_and_ocsf_outputs(self, tmp_path):
        """Both CSV and OCSF outputs are appended to generated_outputs."""
        fw = _make_universal_framework()
        generated = {"compliance": []}

        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="prowler_output",
            provider="aws",
            generated_outputs=generated,
        )

        assert processed == {"test_fw_1.0"}
        assert len(generated["compliance"]) == 2
        assert isinstance(generated["compliance"][0], UniversalComplianceOutput)
        assert isinstance(generated["compliance"][1], OCSFComplianceOutput)

    def test_ocsf_always_generated_no_format_gate(self, tmp_path):
        """OCSF output is generated regardless of output_formats — no gate."""
        fw = _make_universal_framework()
        generated = {"compliance": []}
        process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="prowler_output",
            provider="aws",
            generated_outputs=generated,
        )

        ocsf_outputs = [
            o for o in generated["compliance"] if isinstance(o, OCSFComplianceOutput)
        ]
        assert len(ocsf_outputs) == 1

    def test_csv_file_written(self, tmp_path):
        """CSV file is created with expected content."""
        fw = _make_universal_framework()
        generated = {"compliance": []}
        process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="prowler_output",
            provider="aws",
            generated_outputs=generated,
        )

        csv_path = tmp_path / "compliance" / "prowler_output_test_fw_1.0.csv"
        assert csv_path.exists()
        content = csv_path.read_text()
        assert "PROVIDER" in content
        assert "REQUIREMENTS_ATTRIBUTES_SECTION" in content

    def test_ocsf_file_written(self, tmp_path):
        """OCSF JSON file is created with valid content."""
        fw = _make_universal_framework()
        generated = {"compliance": []}
        process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="prowler_output",
            provider="aws",
            generated_outputs=generated,
        )

        ocsf_path = tmp_path / "compliance" / "prowler_output_test_fw_1.0.ocsf.json"
        assert ocsf_path.exists()
        data = json.loads(ocsf_path.read_text())
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["class_uid"] == 2003

    def test_returns_processed_names(self, tmp_path):
        """Returns the set of framework names that were processed."""
        fw = _make_universal_framework()
        generated = {"compliance": []}

        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0", "legacy_fw"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        assert processed == {"test_fw_1.0"}
        assert "legacy_fw" not in processed


class TestSkipConditions:
    """Tests for frameworks that should NOT be processed."""

    def test_skips_framework_not_in_universal(self, tmp_path):
        """Frameworks not in universal_frameworks dict are skipped."""
        generated = {"compliance": []}

        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks={"cis_aws_1.4"},
            universal_frameworks={},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        assert processed == set()
        assert len(generated["compliance"]) == 0

    def test_skips_framework_without_outputs(self, tmp_path):
        """Frameworks with outputs=None are skipped."""
        fw = _make_universal_framework(with_table_config=False)
        # outputs is None since with_table_config=False
        assert fw.outputs is None
        generated = {"compliance": []}

        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        assert processed == set()
        assert len(generated["compliance"]) == 0

    def test_skips_framework_with_outputs_but_no_table_config(self, tmp_path):
        """Frameworks with outputs but table_config=None are skipped."""
        fw = _make_universal_framework()
        # Manually set table_config to None while keeping outputs
        fw.outputs = OutputsConfig(table_config=None)
        generated = {"compliance": []}

        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        assert processed == set()
        assert len(generated["compliance"]) == 0

    def test_empty_input_frameworks(self, tmp_path):
        """No processing when input set is empty."""
        fw = _make_universal_framework()
        generated = {"compliance": []}

        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks=set(),
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        assert processed == set()
        assert len(generated["compliance"]) == 0


class TestMixedFrameworks:
    """Tests with a mix of universal and legacy frameworks."""

    def test_only_universal_processed_legacy_untouched(self, tmp_path):
        """Only universal frameworks are processed; legacy names are not returned."""
        universal_fw = _make_universal_framework()
        generated = {"compliance": []}

        all_frameworks = {"test_fw_1.0", "cis_aws_1.4", "nist_800_53_aws"}
        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks=all_frameworks,
            universal_frameworks={"test_fw_1.0": universal_fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        assert processed == {"test_fw_1.0"}
        # 2 outputs for the one universal framework (CSV + OCSF)
        assert len(generated["compliance"]) == 2

    def test_removal_from_input_set(self, tmp_path):
        """Caller can subtract processed set from input to get legacy-only frameworks."""
        universal_fw = _make_universal_framework()
        generated = {"compliance": []}

        input_frameworks = {"test_fw_1.0", "cis_aws_1.4", "nist_800_53_aws"}
        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks=input_frameworks,
            universal_frameworks={"test_fw_1.0": universal_fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        remaining = input_frameworks - processed
        assert remaining == {"cis_aws_1.4", "nist_800_53_aws"}

    def test_multiple_universal_frameworks(self, tmp_path):
        """Multiple universal frameworks each get CSV + OCSF."""
        fw1 = _make_universal_framework(name="FW1", version="1.0")
        fw2 = _make_universal_framework(name="FW2", version="2.0")
        generated = {"compliance": []}

        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks={"fw1_1.0", "fw2_2.0", "legacy"},
            universal_frameworks={"fw1_1.0": fw1, "fw2_2.0": fw2},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        assert processed == {"fw1_1.0", "fw2_2.0"}
        # 2 frameworks × 2 outputs each = 4
        assert len(generated["compliance"]) == 4
        csv_outputs = [
            o
            for o in generated["compliance"]
            if isinstance(o, UniversalComplianceOutput)
        ]
        ocsf_outputs = [
            o for o in generated["compliance"] if isinstance(o, OCSFComplianceOutput)
        ]
        assert len(csv_outputs) == 2
        assert len(ocsf_outputs) == 2


class TestProviderVariants:
    """Verify the function works for different providers."""

    @pytest.mark.parametrize(
        "provider",
        [
            "aws",
            "azure",
            "gcp",
            "kubernetes",
            "m365",
            "github",
            "oraclecloud",
            "alibabacloud",
            "nhn",
        ],
    )
    def test_all_providers_produce_outputs(self, tmp_path, provider):
        """Each provider generates CSV + OCSF when given a universal framework."""
        fw = _make_universal_framework()
        generated = {"compliance": []}

        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a", provider=provider)],
            output_directory=str(tmp_path),
            output_filename="out",
            provider=provider,
            generated_outputs=generated,
        )

        assert processed == {"test_fw_1.0"}
        assert len(generated["compliance"]) == 2
        assert isinstance(generated["compliance"][0], UniversalComplianceOutput)
        assert isinstance(generated["compliance"][1], OCSFComplianceOutput)


class TestEmptyFindings:
    """Test behavior when there are no findings."""

    def test_still_processed_with_empty_findings(self, tmp_path):
        """Framework is still marked as processed even with no findings."""
        fw = _make_universal_framework()
        generated = {"compliance": []}

        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        assert processed == {"test_fw_1.0"}
        # Outputs are still appended (they'll just have empty data)
        assert len(generated["compliance"]) == 2


class TestFilePaths:
    """Verify correct file path construction."""

    def test_csv_path_format(self, tmp_path):
        """CSV output has the correct file path."""
        fw = _make_universal_framework()
        generated = {"compliance": []}

        process_universal_compliance_frameworks(
            input_compliance_frameworks={"csa_ccm_4.0"},
            universal_frameworks={"csa_ccm_4.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="prowler_report",
            provider="aws",
            generated_outputs=generated,
        )

        csv_output = generated["compliance"][0]
        assert csv_output.file_path == (
            f"{tmp_path}/compliance/prowler_report_csa_ccm_4.0.csv"
        )

    def test_ocsf_path_format(self, tmp_path):
        """OCSF output has the correct file path."""
        fw = _make_universal_framework()
        generated = {"compliance": []}

        process_universal_compliance_frameworks(
            input_compliance_frameworks={"csa_ccm_4.0"},
            universal_frameworks={"csa_ccm_4.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="prowler_report",
            provider="aws",
            generated_outputs=generated,
        )

        ocsf_output = generated["compliance"][1]
        assert ocsf_output.file_path == (
            f"{tmp_path}/compliance/prowler_report_csa_ccm_4.0.ocsf.json"
        )


# ── Tests for --list-compliance fix ──────────────────────────────────


def _make_legacy_compliance():
    """Create a mock legacy Compliance-like object with the expected attributes."""
    return SimpleNamespace(
        Framework="CIS",
        Provider="AWS",
        Version="1.4",
        Requirements=[
            SimpleNamespace(
                Id="2.1.3",
                Description="Ensure MFA Delete is enabled",
                Checks=["s3_bucket_mfa_delete"],
            ),
        ],
    )


class TestPrintComplianceFrameworks:
    """Tests for print_compliance_frameworks with universal frameworks."""

    def test_includes_universal_frameworks(self, capsys):
        """Universal frameworks appear in the listing."""
        legacy = {"cis_1.4_aws": _make_legacy_compliance()}
        universal = {"csa_ccm_4.0": _make_universal_framework()}
        merged = {**legacy, **universal}

        print_compliance_frameworks(merged)
        captured = capsys.readouterr().out

        assert "cis_1.4_aws" in captured
        assert "csa_ccm_4.0" in captured

    def test_count_includes_both(self, capsys):
        """Framework count includes both legacy and universal."""
        legacy = {"cis_1.4_aws": _make_legacy_compliance()}
        universal = {"csa_ccm_4.0": _make_universal_framework()}
        merged = {**legacy, **universal}

        print_compliance_frameworks(merged)
        captured = capsys.readouterr().out

        assert "2" in captured

    def test_universal_only(self, capsys):
        """Works when only universal frameworks are present."""
        universal = {"csa_ccm_4.0": _make_universal_framework()}

        print_compliance_frameworks(universal)
        captured = capsys.readouterr().out

        assert "csa_ccm_4.0" in captured
        assert "1" in captured


class TestPrintComplianceRequirements:
    """Tests for print_compliance_requirements with universal frameworks."""

    def test_list_checks_universal_framework(self, capsys):
        """Requirements with dict checks are printed correctly."""
        fw = _make_universal_framework()
        all_fw = {"test_fw_1.0": fw}

        print_compliance_requirements(all_fw, ["test_fw_1.0"])
        captured = capsys.readouterr().out

        assert "1.1" in captured
        assert "check_a" in captured

    def test_dict_checks_universal_framework(self, capsys):
        """Requirements with dict checks show provider-prefixed checks."""
        reqs = [
            UniversalComplianceRequirement(
                id="A&A-01",
                description="Audit & Assurance",
                attributes={"Section": "A&A"},
                checks={"aws": ["check_a", "check_b"], "azure": ["check_c"]},
            ),
        ]
        fw = ComplianceFramework(
            framework="CSA_CCM",
            name="CSA CCM 4.0",
            version="4.0",
            description="Cloud Controls Matrix",
            requirements=reqs,
        )
        all_fw = {"csa_ccm_4.0": fw}

        print_compliance_requirements(all_fw, ["csa_ccm_4.0"])
        captured = capsys.readouterr().out

        assert "A&A-01" in captured
        assert "[aws] check_a" in captured
        assert "[aws] check_b" in captured
        assert "[azure] check_c" in captured

    def test_none_provider_shows_multi_provider(self, capsys):
        """Frameworks with provider=None show 'Multi-provider'."""
        fw = ComplianceFramework(
            framework="CSA_CCM",
            name="CSA CCM 4.0",
            version="4.0",
            description="Cloud Controls Matrix",
            requirements=[
                UniversalComplianceRequirement(
                    id="1.1",
                    description="test",
                    attributes={},
                    checks={"aws": ["check_a"]},
                ),
            ],
        )
        all_fw = {"csa_ccm_4.0": fw}

        print_compliance_requirements(all_fw, ["csa_ccm_4.0"])
        captured = capsys.readouterr().out

        assert "Multi-provider" in captured
