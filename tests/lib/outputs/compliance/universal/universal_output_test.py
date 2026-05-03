from types import SimpleNamespace

from prowler.lib.check.compliance_models import (
    AttributeMetadata,
    ComplianceFramework,
    OutputFormats,
    OutputsConfig,
    TableConfig,
    UniversalComplianceRequirement,
)
from prowler.lib.outputs.compliance.universal.universal_output import (
    UniversalComplianceOutput,
)


def _make_finding(check_id, status="PASS", compliance_map=None):
    """Create a mock Finding for output tests."""
    finding = SimpleNamespace()
    finding.provider = "aws"
    finding.account_uid = "123456789012"
    finding.account_name = "test-account"
    finding.region = "us-east-1"
    finding.status = status
    finding.status_extended = f"{check_id} is {status}"
    finding.resource_uid = f"arn:aws:iam::123456789012:{check_id}"
    finding.resource_name = check_id
    finding.muted = False
    finding.check_id = check_id
    finding.metadata = SimpleNamespace(
        Provider="aws",
        CheckID=check_id,
        Severity="medium",
    )
    finding.compliance = compliance_map or {}
    return finding


def _make_framework(requirements, attrs_metadata=None, table_config=None):
    return ComplianceFramework(
        framework="TestFW",
        name="Test Framework",
        provider="AWS",
        version="1.0",
        description="Test framework",
        requirements=requirements,
        attributes_metadata=attrs_metadata,
        outputs=OutputsConfig(table_config=table_config) if table_config else None,
    )


class TestDynamicCSVColumns:
    def test_columns_match_metadata(self, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM", "SubSection": "Auth"},
                checks={"aws": ["check_a"]},
            ),
        ]
        metadata = [
            AttributeMetadata(key="Section", type="str"),
            AttributeMetadata(key="SubSection", type="str"),
        ]
        fw = _make_framework(reqs, metadata, TableConfig(group_by="Section"))

        findings = [
            _make_finding("check_a", "PASS", {"TestFW-1.0": ["1.1"]}),
        ]
        filepath = str(tmp_path / "test.csv")

        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=filepath,
        )

        assert len(output.data) == 1
        row_dict = output.data[0].dict()
        assert "Requirements_Attributes_Section" in row_dict
        assert "Requirements_Attributes_SubSection" in row_dict
        assert row_dict["Requirements_Attributes_Section"] == "IAM"
        assert row_dict["Requirements_Attributes_SubSection"] == "Auth"


class TestManualRequirements:
    def test_manual_status(self, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"]},
            ),
            UniversalComplianceRequirement(
                id="manual-1",
                description="manual check",
                attributes={"Section": "Governance"},
                checks={},
            ),
        ]
        metadata = [
            AttributeMetadata(key="Section", type="str"),
        ]
        fw = _make_framework(reqs, metadata, TableConfig(group_by="Section"))

        findings = [
            _make_finding("check_a", "PASS", {"TestFW-1.0": ["1.1"]}),
        ]
        filepath = str(tmp_path / "test.csv")

        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=filepath,
        )

        # Should have 1 real finding + 1 manual
        assert len(output.data) == 2
        manual_rows = [r for r in output.data if r.dict()["Status"] == "MANUAL"]
        assert len(manual_rows) == 1
        assert manual_rows[0].dict()["Requirements_Id"] == "manual-1"
        assert manual_rows[0].dict()["ResourceId"] == "manual_check"


class TestMITREExtraColumns:
    def test_mitre_columns_present(self, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="T1190",
                description="Exploit",
                attributes={},
                checks={"aws": ["check_a"]},
                tactics=["Initial Access"],
                sub_techniques=[],
                platforms=["IaaS"],
                technique_url="https://attack.mitre.org/techniques/T1190/",
            ),
        ]
        fw = _make_framework(reqs, None, TableConfig(group_by="_Tactics"))

        findings = [
            _make_finding("check_a", "PASS", {"TestFW-1.0": ["T1190"]}),
        ]
        filepath = str(tmp_path / "test.csv")

        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=filepath,
        )

        assert len(output.data) == 1
        row_dict = output.data[0].dict()
        assert "Requirements_Tactics" in row_dict
        assert row_dict["Requirements_Tactics"] == "Initial Access"
        assert "Requirements_TechniqueURL" in row_dict


class TestCSVFileWrite:
    def test_batch_write(self, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"]},
            ),
        ]
        metadata = [
            AttributeMetadata(key="Section", type="str"),
        ]
        fw = _make_framework(reqs, metadata, TableConfig(group_by="Section"))

        findings = [
            _make_finding("check_a", "PASS", {"TestFW-1.0": ["1.1"]}),
        ]
        filepath = str(tmp_path / "test.csv")

        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=filepath,
        )
        output.batch_write_data_to_file()

        # Verify file was created and has content
        with open(filepath, "r") as f:
            content = f.read()
        assert "PROVIDER" in content  # Headers are uppercase
        assert "REQUIREMENTS_ATTRIBUTES_SECTION" in content
        assert "IAM" in content


class TestNoFindings:
    def test_empty_findings_no_data(self, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"]},
            ),
        ]
        fw = _make_framework(reqs, None, TableConfig(group_by="Section"))
        filepath = str(tmp_path / "test.csv")

        output = UniversalComplianceOutput(
            findings=[],
            framework=fw,
            file_path=filepath,
        )
        assert len(output.data) == 0


class TestMultiProviderOutput:
    def test_dict_checks_filtered_by_provider(self, tmp_path):
        """Only checks for the given provider appear in CSV output."""
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
        ]
        metadata = [
            AttributeMetadata(key="Section", type="str"),
        ]
        fw = ComplianceFramework(
            framework="MultiCloud",
            name="Multi",
            version="1.0",
            description="Test multi-provider",
            requirements=reqs,
            attributes_metadata=metadata,
            outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
        )

        findings = [
            _make_finding("check_a", "PASS", {"MultiCloud-1.0": ["1.1"]}),
            _make_finding("check_b", "FAIL", {"MultiCloud-1.0": ["1.1"]}),
        ]
        filepath = str(tmp_path / "test.csv")

        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=filepath,
            provider="aws",
        )

        # Only check_a should match (it's the AWS check)
        assert len(output.data) == 1
        row_dict = output.data[0].dict()
        assert row_dict["Requirements_Attributes_Section"] == "IAM"

    def test_no_provider_includes_all(self, tmp_path):
        """Without provider filter, all checks from all providers are included."""
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
        ]
        metadata = [
            AttributeMetadata(key="Section", type="str"),
        ]
        fw = ComplianceFramework(
            framework="MultiCloud",
            name="Multi",
            version="1.0",
            description="Test multi-provider",
            requirements=reqs,
            attributes_metadata=metadata,
            outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
        )

        findings = [
            _make_finding("check_a", "PASS", {"MultiCloud-1.0": ["1.1"]}),
            _make_finding("check_b", "FAIL", {"MultiCloud-1.0": ["1.1"]}),
        ]
        filepath = str(tmp_path / "test.csv")

        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=filepath,
        )

        # Both checks should be included without provider filter
        assert len(output.data) == 2

    def test_empty_dict_checks_is_manual(self, tmp_path):
        """Requirement with empty dict checks is treated as manual."""
        reqs = [
            UniversalComplianceRequirement(
                id="manual-1",
                description="manual check",
                attributes={"Section": "Governance"},
                checks={},
            ),
        ]
        metadata = [
            AttributeMetadata(key="Section", type="str"),
        ]
        fw = ComplianceFramework(
            framework="MultiCloud",
            name="Multi",
            version="1.0",
            description="Test",
            requirements=reqs,
            attributes_metadata=metadata,
            outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
        )

        filepath = str(tmp_path / "test.csv")

        output = UniversalComplianceOutput(
            findings=[_make_finding("other_check", "PASS", {})],
            framework=fw,
            file_path=filepath,
            provider="aws",
        )

        manual_rows = [r for r in output.data if r.dict()["Status"] == "MANUAL"]
        assert len(manual_rows) == 1
        assert manual_rows[0].dict()["Requirements_Id"] == "manual-1"


class TestCSVExclude:
    def test_csv_false_excludes_column(self, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM", "Internal": "hidden"},
                checks={"aws": ["check_a"]},
            ),
        ]
        metadata = [
            AttributeMetadata(
                key="Section", type="str", output_formats=OutputFormats(csv=True)
            ),
            AttributeMetadata(
                key="Internal", type="str", output_formats=OutputFormats(csv=False)
            ),
        ]
        fw = _make_framework(reqs, metadata, TableConfig(group_by="Section"))

        findings = [
            _make_finding("check_a", "PASS", {"TestFW-1.0": ["1.1"]}),
        ]
        filepath = str(tmp_path / "test.csv")

        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=filepath,
        )

        row_dict = output.data[0].dict()
        assert "Requirements_Attributes_Section" in row_dict
        assert "Requirements_Attributes_Internal" not in row_dict


def _make_provider_finding(provider, check_id="check_a", status="PASS"):
    """Create a mock Finding with a specific provider."""
    finding = _make_finding(check_id, status, {"TestFW-1.0": ["1.1"]})
    finding.provider = provider
    return finding


def _simple_framework():
    all_providers = [
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "m365",
        "github",
        "oraclecloud",
        "alibabacloud",
        "nhn",
        "unknown",
    ]
    reqs = [
        UniversalComplianceRequirement(
            id="1.1",
            description="test",
            attributes={"Section": "IAM"},
            checks={p: ["check_a"] for p in all_providers},
        ),
    ]
    metadata = [
        AttributeMetadata(key="Section", type="str"),
    ]
    return _make_framework(reqs, metadata, TableConfig(group_by="Section"))


class TestProviderHeaders:
    def test_aws_headers(self, tmp_path):
        fw = _simple_framework()
        findings = [_make_provider_finding("aws")]
        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=str(tmp_path / "test.csv"),
            provider="aws",
        )
        row_dict = output.data[0].dict()
        assert "AccountId" in row_dict
        assert "Region" in row_dict
        assert row_dict["AccountId"] == "123456789012"
        assert row_dict["Region"] == "us-east-1"

    def test_azure_headers(self, tmp_path):
        fw = _simple_framework()
        findings = [_make_provider_finding("azure")]
        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=str(tmp_path / "test.csv"),
            provider="azure",
        )
        row_dict = output.data[0].dict()
        assert "SubscriptionId" in row_dict
        assert "Location" in row_dict
        assert row_dict["SubscriptionId"] == "123456789012"
        assert row_dict["Location"] == "us-east-1"

    def test_gcp_headers(self, tmp_path):
        fw = _simple_framework()
        findings = [_make_provider_finding("gcp")]
        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=str(tmp_path / "test.csv"),
            provider="gcp",
        )
        row_dict = output.data[0].dict()
        assert "ProjectId" in row_dict
        assert "Location" in row_dict
        assert row_dict["ProjectId"] == "123456789012"

    def test_kubernetes_headers(self, tmp_path):
        fw = _simple_framework()
        findings = [_make_provider_finding("kubernetes")]
        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=str(tmp_path / "test.csv"),
            provider="kubernetes",
        )
        row_dict = output.data[0].dict()
        assert "Context" in row_dict
        assert "Namespace" in row_dict
        # Kubernetes Context maps to account_name
        assert row_dict["Context"] == "test-account"
        assert row_dict["Namespace"] == "us-east-1"

    def test_github_headers(self, tmp_path):
        fw = _simple_framework()
        findings = [_make_provider_finding("github")]
        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=str(tmp_path / "test.csv"),
            provider="github",
        )
        row_dict = output.data[0].dict()
        assert "Account_Name" in row_dict
        assert "Account_Id" in row_dict
        # GitHub: Account_Name (pos 3) from account_name, Account_Id (pos 4) from account_uid
        assert row_dict["Account_Name"] == "test-account"
        assert row_dict["Account_Id"] == "123456789012"
        # Verify column order matches legacy (Account_Name before Account_Id)
        keys = list(row_dict.keys())
        assert keys.index("Account_Name") < keys.index("Account_Id")

    def test_unknown_provider_defaults(self, tmp_path):
        fw = _simple_framework()
        findings = [_make_provider_finding("unknown")]
        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=str(tmp_path / "test.csv"),
            provider="unknown",
        )
        row_dict = output.data[0].dict()
        assert "AccountId" in row_dict
        assert "Region" in row_dict

    def test_none_provider_defaults(self, tmp_path):
        fw = _simple_framework()
        findings = [_make_provider_finding("aws")]
        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=str(tmp_path / "test.csv"),
        )
        row_dict = output.data[0].dict()
        assert "AccountId" in row_dict
        assert "Region" in row_dict

    def test_csv_write_azure_headers(self, tmp_path):
        fw = _simple_framework()
        findings = [_make_provider_finding("azure")]
        filepath = str(tmp_path / "test.csv")
        output = UniversalComplianceOutput(
            findings=findings,
            framework=fw,
            file_path=filepath,
            provider="azure",
        )
        output.batch_write_data_to_file()

        with open(filepath, "r") as f:
            content = f.read()
        assert "SUBSCRIPTIONID" in content
        assert "LOCATION" in content
        # Should NOT have the default AccountId/Region headers
        assert "ACCOUNTID" not in content

    def test_column_order_matches_legacy(self, tmp_path):
        """Verify that the base column order matches the legacy per-provider models.

        Legacy models all define: Provider, Description, <col3>, <col4>, AssessmentDate, ...
        The universal output must preserve this exact order for backward compatibility.
        """
        # Expected column order per provider (positions 3 and 4 after Provider, Description)
        legacy_order = {
            "aws": ("AccountId", "Region"),
            "azure": ("SubscriptionId", "Location"),
            "gcp": ("ProjectId", "Location"),
            "kubernetes": ("Context", "Namespace"),
            "m365": ("TenantId", "Location"),
            "github": ("Account_Name", "Account_Id"),
            "oraclecloud": ("TenancyId", "Region"),
            "alibabacloud": ("AccountId", "Region"),
            "nhn": ("AccountId", "Region"),
        }

        for provider_name, (expected_col3, expected_col4) in legacy_order.items():
            fw = _simple_framework()
            findings = [_make_provider_finding(provider_name)]
            output = UniversalComplianceOutput(
                findings=findings,
                framework=fw,
                file_path=str(tmp_path / f"test_{provider_name}.csv"),
                provider=provider_name,
            )
            keys = list(output.data[0].dict().keys())
            assert keys[0] == "Provider", f"{provider_name}: col 1 should be Provider"
            assert (
                keys[1] == "Description"
            ), f"{provider_name}: col 2 should be Description"
            assert (
                keys[2] == expected_col3
            ), f"{provider_name}: col 3 should be {expected_col3}, got {keys[2]}"
            assert (
                keys[3] == expected_col4
            ), f"{provider_name}: col 4 should be {expected_col4}, got {keys[3]}"
            assert (
                keys[4] == "AssessmentDate"
            ), f"{provider_name}: col 5 should be AssessmentDate"
