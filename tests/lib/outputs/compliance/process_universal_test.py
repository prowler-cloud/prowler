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

import csv
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


def _make_framework_with_manual(name="MixedFW", version="1.0"):
    """Framework with one aws-covered requirement and one manual one.

    The manual requirement has no aws checks, so for provider ``aws`` it is
    emitted as a manual row/event — used to assert manual requirements are
    not duplicated when the writer is reused across streaming batches.
    """
    reqs = [
        UniversalComplianceRequirement(
            id="1.1",
            description="Covered requirement",
            attributes={"Section": "IAM"},
            checks={"aws": ["check_a"]},
        ),
        UniversalComplianceRequirement(
            id="2.1",
            description="Manual requirement",
            attributes={"Section": "GOV"},
            checks={"aws": []},
        ),
    ]
    metadata = [AttributeMetadata(key="Section", type="str")]
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


# ── Idempotency tests ────────────────────────────────────────────────


class TestIdempotency:
    """The function must be safe to invoke multiple times for the same
    framework. Repeated calls must reuse writers tracked in
    ``generated_outputs["compliance"]`` instead of recreating them.

    This guards against:
      - duplicate writer entries in generated_outputs (regular pipeline
        treats one writer per framework)
      - the OCSF append-bug where a second writer would emit
        ``[...]<new>...]`` and break the JSON array.
    """

    def test_second_call_does_not_duplicate_writers(self, tmp_path):
        fw = _make_universal_framework()
        generated = {"compliance": []}
        kwargs = dict(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="prowler_output",
            provider="aws",
            generated_outputs=generated,
        )

        first = process_universal_compliance_frameworks(**kwargs)
        first_count = len(generated["compliance"])
        second = process_universal_compliance_frameworks(**kwargs)
        second_count = len(generated["compliance"])

        assert first == {"test_fw_1.0"}
        assert second == {"test_fw_1.0"}  # still reported as processed
        assert first_count == 2  # CSV + OCSF
        assert second_count == 2  # NO duplication

    def test_second_call_keeps_ocsf_json_valid(self, tmp_path):
        """End-to-end: after two calls the OCSF JSON file must still be
        a single, valid JSON array — not the broken ``[...]...]`` form."""
        fw = _make_universal_framework()
        generated = {"compliance": []}
        kwargs = dict(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="prowler_output",
            provider="aws",
            generated_outputs=generated,
        )

        process_universal_compliance_frameworks(**kwargs)
        process_universal_compliance_frameworks(**kwargs)

        ocsf_path = tmp_path / "compliance" / "prowler_output_test_fw_1.0.ocsf.json"
        data = json.loads(ocsf_path.read_text())  # Will raise on invalid JSON
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_reuses_existing_writer_object(self, tmp_path):
        """The CSV/OCSF writer instances appended on first call must be
        the SAME objects after a second call — not fresh ones."""
        fw = _make_universal_framework()
        generated = {"compliance": []}
        kwargs = dict(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="prowler_output",
            provider="aws",
            generated_outputs=generated,
        )

        process_universal_compliance_frameworks(**kwargs)
        first_writers = list(generated["compliance"])
        process_universal_compliance_frameworks(**kwargs)
        second_writers = list(generated["compliance"])

        # Same identity, same length — reused, not recreated.
        assert len(first_writers) == len(second_writers)
        for a, b in zip(first_writers, second_writers):
            assert a is b

    def test_idempotency_across_mixed_frameworks(self, tmp_path):
        """When the second call adds a new framework, the new one is
        created while existing ones are NOT recreated."""
        fw1 = _make_universal_framework(name="FW1", version="1.0")
        fw2 = _make_universal_framework(name="FW2", version="2.0")
        generated = {"compliance": []}

        # First call: only FW1
        process_universal_compliance_frameworks(
            input_compliance_frameworks={"fw1_1.0"},
            universal_frameworks={"fw1_1.0": fw1, "fw2_2.0": fw2},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )
        first_writers = list(generated["compliance"])
        assert len(first_writers) == 2

        # Second call: includes both. FW1 must be reused, FW2 created fresh.
        process_universal_compliance_frameworks(
            input_compliance_frameworks={"fw1_1.0", "fw2_2.0"},
            universal_frameworks={"fw1_1.0": fw1, "fw2_2.0": fw2},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )
        second_writers = list(generated["compliance"])
        assert len(second_writers) == 4  # 2 (FW1 reused) + 2 new (FW2)
        # FW1 writer instances unchanged
        assert second_writers[0] is first_writers[0]
        assert second_writers[1] is first_writers[1]


class TestStreamingBatches:
    """Streaming-aware behaviour: ``from_cli`` / ``is_last`` / ``_flush``.

    Regression coverage for the API streaming path where the helper is
    invoked once per finding batch: before the fix only the first batch
    was written (batches 2..N silently dropped) and manual requirements
    were re-emitted on every batch.
    """

    def _run_batches(self, tmp_path, fw, key, batches):
        """Invoke the helper once per (findings, is_last) batch, sharing
        ``generated_outputs`` so writers are reused like the API does."""
        generated = {"compliance": []}
        for findings, is_last in batches:
            process_universal_compliance_frameworks(
                input_compliance_frameworks={key},
                universal_frameworks={key: fw},
                finding_outputs=findings,
                output_directory=str(tmp_path),
                output_filename="out",
                provider="aws",
                generated_outputs=generated,
                from_cli=False,
                is_last=is_last,
            )
        return generated

    def test_defaults_preserve_cli_single_call(self, tmp_path):
        """Defaults (``from_cli=True``, ``is_last=True``): a single call
        still finalizes a valid, closed OCSF JSON array (CLI unchanged)."""
        fw = _make_universal_framework()
        generated = {"compliance": []}
        process_universal_compliance_frameworks(
            input_compliance_frameworks={"test_fw_1.0"},
            universal_frameworks={"test_fw_1.0": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )
        ocsf_path = tmp_path / "compliance" / "out_test_fw_1.0.ocsf.json"
        data = json.loads(ocsf_path.read_text())
        assert isinstance(data, list) and len(data) >= 1

    def test_multibatch_csv_keeps_every_batch(self, tmp_path):
        """Findings from batches 2..N must not be dropped (the bug)."""
        fw = _make_universal_framework()
        f1 = _make_finding("check_a", status="PASS")
        f2 = _make_finding("check_a", status="FAIL")
        generated = self._run_batches(
            tmp_path, fw, "fw_1.0", [([f1], False), ([f2], True)]
        )
        content = (tmp_path / "compliance" / "out_fw_1.0.csv").read_text()
        assert "check_a is PASS" in content  # batch 1
        assert "check_a is FAIL" in content  # batch 2 — regression
        # writer reused, not recreated: still just 1 CSV + 1 OCSF
        assert len(generated["compliance"]) == 2

    def test_multibatch_ocsf_valid_array_with_every_batch(self, tmp_path):
        """OCSF is a valid (closed) JSON array holding every batch's
        events only after the ``is_last=True`` call."""
        fw = _make_universal_framework()
        f1 = _make_finding("check_a", status="PASS")
        f2 = _make_finding("check_a", status="FAIL")
        self._run_batches(tmp_path, fw, "fw_1.0", [([f1], False), ([f2], True)])
        data = json.loads(
            (tmp_path / "compliance" / "out_fw_1.0.ocsf.json").read_text()
        )
        assert isinstance(data, list)
        assert len(data) >= 2  # one event per batch finding

    def test_manual_requirement_not_duplicated_across_batches(self, tmp_path):
        """Manual requirement is emitted once (first batch, via __init__),
        never re-emitted when the writer is reused (``include_manual=False``)."""
        fw = _make_framework_with_manual()
        f1 = _make_finding("check_a", status="PASS")
        f2 = _make_finding("check_a", status="FAIL")
        self._run_batches(tmp_path, fw, "fw_1.0", [([f1], False), ([f2], True)])
        rows = list(
            csv.DictReader(
                (tmp_path / "compliance" / "out_fw_1.0.csv").read_text().splitlines(),
                delimiter=";",
            )
        )
        manual_rows = [r for r in rows if r["STATUS"] == "MANUAL"]
        assert len(manual_rows) == 1
        assert manual_rows[0]["REQUIREMENTS_ID"] == "2.1"

        ocsf = json.loads(
            (tmp_path / "compliance" / "out_fw_1.0.ocsf.json").read_text()
        )
        manual_events = [
            e
            for e in ocsf
            if (e.get("compliance") or {}).get("requirements") == ["2.1"]
        ]
        assert len(manual_events) == 1

    def test_writer_reused_not_recreated_across_batches(self, tmp_path):
        """Three batches still yield exactly one CSV + one OCSF writer,
        and the same instances are reused throughout."""
        fw = _make_universal_framework()
        generated = self._run_batches(
            tmp_path,
            fw,
            "fw_1.0",
            [
                ([_make_finding("check_a")], False),
                ([_make_finding("check_a")], False),
                ([_make_finding("check_a")], True),
            ],
        )
        assert len(generated["compliance"]) == 2
        assert isinstance(generated["compliance"][0], UniversalComplianceOutput)
        assert isinstance(generated["compliance"][1], OCSFComplianceOutput)

    def test_label_without_version_still_outputs(self, tmp_path):
        """Empty framework version → label is the framework name only;
        the helper still produces both artifacts without error."""
        fw = _make_universal_framework(version="")
        generated = {"compliance": []}
        processed = process_universal_compliance_frameworks(
            input_compliance_frameworks={"fw"},
            universal_frameworks={"fw": fw},
            finding_outputs=[_make_finding("check_a")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
            from_cli=False,
            is_last=True,
        )
        assert processed == {"fw"}
        assert len(generated["compliance"]) == 2
        assert (tmp_path / "compliance" / "out_fw.csv").exists()
        assert (tmp_path / "compliance" / "out_fw.ocsf.json").exists()


class TestMultiProviderUniversalFramework:
    """A top-level CSA-CCM-style framework must produce a CSV+OCSF pair
    scoped to the provider it is invoked with."""

    def _make_csa_like_framework(self):
        reqs = [
            UniversalComplianceRequirement(
                id="A&A-01",
                description="Audit and Assurance",
                attributes={"Section": "Audit"},
                checks={
                    "aws": ["aws_check"],
                    "azure": ["azure_check"],
                    "gcp": ["gcp_check"],
                },
            ),
        ]
        outputs = OutputsConfig(table_config=TableConfig(group_by="Section"))
        return ComplianceFramework(
            framework="CSA_CCM",
            name="CSA Cloud Controls Matrix",
            version="4.0",
            description="Multi-provider framework",
            requirements=reqs,
            attributes_metadata=[AttributeMetadata(key="Section", type="str")],
            outputs=outputs,
        )

    @pytest.mark.parametrize(
        "provider,check_id",
        [
            ("aws", "aws_check"),
            ("azure", "azure_check"),
            ("gcp", "gcp_check"),
        ],
    )
    def test_per_provider_outputs_isolated(self, tmp_path, provider, check_id):
        fw = self._make_csa_like_framework()
        generated = {"compliance": []}

        process_universal_compliance_frameworks(
            input_compliance_frameworks={"csa_ccm_4.0"},
            universal_frameworks={"csa_ccm_4.0": fw},
            finding_outputs=[_make_finding(check_id, provider=provider)],
            output_directory=str(tmp_path),
            output_filename="prowler_output",
            provider=provider,
            generated_outputs=generated,
        )

        ocsf_path = tmp_path / "compliance" / "prowler_output_csa_ccm_4.0.ocsf.json"
        data = json.loads(ocsf_path.read_text())
        assert isinstance(data, list)
        non_manual = [d for d in data if d.get("status_code") != "MANUAL"]
        assert len(non_manual) == 1
        assert non_manual[0]["compliance"]["checks"][0]["uid"] == check_id


class TestMitreStyleOCSFOutput:
    """MITRE attrs wrapped as `{"_raw_attributes": [...]}` must not leak
    the marker key through the OCSF pipeline."""

    def test_mitre_raw_attributes_pass_through_pipeline(self, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="T1078",
                description="Valid Accounts",
                attributes={
                    "_raw_attributes": [
                        {"AWSService": "IAM", "Category": "Initial Access"},
                    ]
                },
                checks={"aws": ["check_a"]},
            ),
        ]
        outputs = OutputsConfig(table_config=TableConfig(group_by="AWSService"))
        fw = ComplianceFramework(
            framework="MITRE",
            name="MITRE ATT&CK",
            version="14",
            description="Mitre",
            requirements=reqs,
            outputs=outputs,
        )
        generated = {"compliance": []}

        process_universal_compliance_frameworks(
            input_compliance_frameworks={"mitre_attack_aws"},
            universal_frameworks={"mitre_attack_aws": fw},
            finding_outputs=[_make_finding("check_a", "PASS")],
            output_directory=str(tmp_path),
            output_filename="out",
            provider="aws",
            generated_outputs=generated,
        )

        ocsf_path = tmp_path / "compliance" / "out_mitre_attack_aws.ocsf.json"
        data = json.loads(ocsf_path.read_text())
        assert isinstance(data, list) and len(data) >= 1
        for event in data:
            attrs = (event.get("unmapped") or {}).get("requirement_attributes", {})
            assert "_raw_attributes" not in attrs
            assert "raw_attributes" not in attrs
