from types import SimpleNamespace
from unittest.mock import MagicMock

from prowler.lib.check.compliance_models import (
    ComplianceFramework,
    OutputsConfig,
    ScoringConfig,
    SplitByConfig,
    TableConfig,
    TableLabels,
    UniversalComplianceRequirement,
)
from prowler.lib.outputs.compliance.universal.universal_table import (
    _build_requirement_check_map,
    _get_group_key,
    get_universal_table,
)


def _make_finding(check_id, status="PASS", muted=False):
    """Create a mock finding for table tests."""
    finding = SimpleNamespace()
    finding.check_metadata = SimpleNamespace(CheckID=check_id)
    finding.status = status
    finding.muted = muted
    return finding


def _make_framework(requirements, table_config, provider="AWS"):
    return ComplianceFramework(
        Framework="TestFW",
        Name="Test Framework",
        Provider=provider,
        Version="1.0",
        Description="Test",
        Requirements=requirements,
        Outputs=OutputsConfig(Table_Config=table_config) if table_config else None,
    )


class TestBuildRequirementCheckMap:
    def test_basic(self):
        reqs = [
            UniversalComplianceRequirement(
                Id="1.1",
                Description="test",
                Attributes={"Section": "IAM"},
                Checks=["check_a", "check_b"],
            ),
            UniversalComplianceRequirement(
                Id="1.2",
                Description="test2",
                Attributes={"Section": "IAM"},
                Checks=["check_b", "check_c"],
            ),
        ]
        fw = _make_framework(reqs, TableConfig(GroupBy="Section"))
        check_map = _build_requirement_check_map(fw)
        assert "check_a" in check_map
        assert len(check_map["check_b"]) == 2
        assert "check_c" in check_map

    def test_dict_checks_no_provider_filter(self):
        reqs = [
            UniversalComplianceRequirement(
                Id="1.1",
                Description="test",
                Attributes={"Section": "IAM"},
                Checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
        ]
        fw = _make_framework(reqs, TableConfig(GroupBy="Section"))
        check_map = _build_requirement_check_map(fw)
        assert "check_a" in check_map
        assert "check_b" in check_map

    def test_dict_checks_filtered_by_provider(self):
        reqs = [
            UniversalComplianceRequirement(
                Id="1.1",
                Description="test",
                Attributes={"Section": "IAM"},
                Checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
        ]
        fw = _make_framework(reqs, TableConfig(GroupBy="Section"))
        check_map = _build_requirement_check_map(fw, provider="aws")
        assert "check_a" in check_map
        assert "check_b" not in check_map

    def test_dict_checks_provider_not_present(self):
        reqs = [
            UniversalComplianceRequirement(
                Id="1.1",
                Description="test",
                Attributes={"Section": "IAM"},
                Checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
        ]
        fw = _make_framework(reqs, TableConfig(GroupBy="Section"))
        check_map = _build_requirement_check_map(fw, provider="gcp")
        assert len(check_map) == 0


class TestGetGroupKey:
    def test_normal_field(self):
        req = UniversalComplianceRequirement(
            Id="1.1",
            Description="test",
            Attributes={"Section": "IAM"},
            Checks=[],
        )
        assert _get_group_key(req, "Section") == ["IAM"]

    def test_tactics(self):
        req = UniversalComplianceRequirement(
            Id="T1190",
            Description="test",
            Attributes={},
            Checks=[],
            Tactics=["Initial Access", "Execution"],
        )
        assert _get_group_key(req, "_Tactics") == ["Initial Access", "Execution"]


class TestGroupedMode:
    def test_grouped_rendering(self, capsys):
        reqs = [
            UniversalComplianceRequirement(
                Id="1.1",
                Description="test",
                Attributes={"Section": "IAM"},
                Checks=["check_a"],
            ),
            UniversalComplianceRequirement(
                Id="2.1",
                Description="test2",
                Attributes={"Section": "Logging"},
                Checks=["check_b"],
            ),
        ]
        tc = TableConfig(GroupBy="Section")
        fw = _make_framework(reqs, tc)

        findings = [
            _make_finding("check_a", "PASS"),
            _make_finding("check_b", "FAIL"),
        ]
        bulk_metadata = {
            "check_a": MagicMock(Compliance=[]),
            "check_b": MagicMock(Compliance=[]),
        }

        get_universal_table(
            findings,
            bulk_metadata,
            "test_fw",
            "output",
            "/tmp",
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        assert "IAM" in captured.out
        assert "Logging" in captured.out
        assert "PASS" in captured.out
        assert "FAIL" in captured.out


class TestSplitMode:
    def test_split_rendering(self, capsys):
        reqs = [
            UniversalComplianceRequirement(
                Id="1.1",
                Description="test",
                Attributes={"Section": "Storage", "Profile": "Level 1"},
                Checks=["check_a"],
            ),
            UniversalComplianceRequirement(
                Id="1.2",
                Description="test2",
                Attributes={"Section": "Storage", "Profile": "Level 2"},
                Checks=["check_b"],
            ),
        ]
        tc = TableConfig(
            GroupBy="Section",
            SplitBy=SplitByConfig(Field="Profile", Values=["Level 1", "Level 2"]),
        )
        fw = _make_framework(reqs, tc)

        findings = [
            _make_finding("check_a", "PASS"),
            _make_finding("check_b", "FAIL"),
        ]
        bulk_metadata = {
            "check_a": MagicMock(Compliance=[]),
            "check_b": MagicMock(Compliance=[]),
        }

        get_universal_table(
            findings,
            bulk_metadata,
            "test_fw",
            "output",
            "/tmp",
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        assert "Storage" in captured.out
        assert "Level 1" in captured.out
        assert "Level 2" in captured.out


class TestScoredMode:
    def test_scored_rendering(self, capsys):
        reqs = [
            UniversalComplianceRequirement(
                Id="1.1",
                Description="test",
                Attributes={"Section": "IAM", "LevelOfRisk": 5, "Weight": 100},
                Checks=["check_a"],
            ),
            UniversalComplianceRequirement(
                Id="1.2",
                Description="test2",
                Attributes={"Section": "IAM", "LevelOfRisk": 3, "Weight": 50},
                Checks=["check_b"],
            ),
        ]
        tc = TableConfig(
            GroupBy="Section",
            Scoring=ScoringConfig(RiskField="LevelOfRisk", WeightField="Weight"),
        )
        fw = _make_framework(reqs, tc)

        findings = [
            _make_finding("check_a", "PASS"),
            _make_finding("check_b", "FAIL"),
        ]
        bulk_metadata = {
            "check_a": MagicMock(Compliance=[]),
            "check_b": MagicMock(Compliance=[]),
        }

        get_universal_table(
            findings,
            bulk_metadata,
            "test_fw",
            "output",
            "/tmp",
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        assert "IAM" in captured.out
        assert "Score" in captured.out
        assert "Threat Score" in captured.out


class TestCustomLabels:
    def test_ens_spanish_labels(self, capsys):
        reqs = [
            UniversalComplianceRequirement(
                Id="1.1",
                Description="test",
                Attributes={"Marco": "operacional"},
                Checks=["check_a"],
            ),
            UniversalComplianceRequirement(
                Id="1.2",
                Description="test2",
                Attributes={"Marco": "organizativo"},
                Checks=["check_b"],
            ),
        ]
        tc = TableConfig(
            GroupBy="Marco",
            Labels=TableLabels(
                PassLabel="CUMPLE",
                FailLabel="NO CUMPLE",
                ProviderHeader="Proveedor",
                Title="Estado de Cumplimiento",
            ),
        )
        fw = _make_framework(reqs, tc)

        findings = [_make_finding("check_a", "PASS"), _make_finding("check_b", "FAIL")]
        bulk_metadata = {
            "check_a": MagicMock(Compliance=[]),
            "check_b": MagicMock(Compliance=[]),
        }

        get_universal_table(
            findings,
            bulk_metadata,
            "test_fw",
            "output",
            "/tmp",
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        assert "CUMPLE" in captured.out
        assert "Estado de Cumplimiento" in captured.out


class TestMultiProviderDictChecks:
    def test_only_aws_checks_matched(self, capsys):
        """With dict Checks and provider='aws', only AWS checks match findings."""
        reqs = [
            UniversalComplianceRequirement(
                Id="1.1",
                Description="test",
                Attributes={"Section": "IAM"},
                Checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
            UniversalComplianceRequirement(
                Id="2.1",
                Description="test2",
                Attributes={"Section": "Logging"},
                Checks={"aws": ["check_c"], "gcp": ["check_d"]},
            ),
        ]
        tc = TableConfig(GroupBy="Section")
        fw = ComplianceFramework(
            Framework="MultiCloud",
            Name="Multi",
            Description="Test",
            Requirements=reqs,
            Outputs=OutputsConfig(Table_Config=tc),
        )

        findings = [
            _make_finding("check_a", "PASS"),
            _make_finding("check_b", "FAIL"),  # Azure check, should be ignored
            _make_finding("check_c", "PASS"),
        ]
        bulk_metadata = {
            "check_a": MagicMock(Compliance=[]),
            "check_b": MagicMock(Compliance=[]),
            "check_c": MagicMock(Compliance=[]),
        }

        get_universal_table(
            findings,
            bulk_metadata,
            "multi_cloud",
            "output",
            "/tmp",
            False,
            framework=fw,
            provider="aws",
        )

        captured = capsys.readouterr()
        assert "IAM" in captured.out
        assert "Logging" in captured.out
        # check_b (azure) should not have been counted as FAIL for AWS
        assert "PASS" in captured.out


class TestNoTableConfig:
    def test_returns_early_without_table_config(self, capsys):
        fw = ComplianceFramework(
            Framework="TestFW",
            Name="Test",
            Provider="AWS",
            Description="Test",
            Requirements=[],
        )
        get_universal_table([], {}, "test", "out", "/tmp", False, framework=fw)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_returns_early_without_framework(self, capsys):
        get_universal_table([], {}, "test", "out", "/tmp", False, framework=None)
        captured = capsys.readouterr()
        assert captured.out == ""
