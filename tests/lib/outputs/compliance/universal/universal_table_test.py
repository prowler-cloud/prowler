import re
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


def _strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _make_framework(requirements, table_config, provider="AWS"):
    return ComplianceFramework(
        framework="TestFW",
        name="Test Framework",
        provider=provider,
        version="1.0",
        description="Test",
        requirements=requirements,
        outputs=OutputsConfig(table_config=table_config) if table_config else None,
    )


class TestBuildRequirementCheckMap:
    """Test cases for building the requirement-to-check map of a framework."""

    def test_basic(self):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a", "check_b"]},
            ),
            UniversalComplianceRequirement(
                id="1.2",
                description="test2",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_b", "check_c"]},
            ),
        ]
        fw = _make_framework(reqs, TableConfig(group_by="Section"))
        check_map = _build_requirement_check_map(fw)
        assert "check_a" in check_map
        assert len(check_map["check_b"]) == 2
        assert "check_c" in check_map

    def test_dict_checks_no_provider_filter(self):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
        ]
        fw = _make_framework(reqs, TableConfig(group_by="Section"))
        check_map = _build_requirement_check_map(fw)
        assert "check_a" in check_map
        assert "check_b" in check_map

    def test_dict_checks_filtered_by_provider(self):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
        ]
        fw = _make_framework(reqs, TableConfig(group_by="Section"))
        check_map = _build_requirement_check_map(fw, provider="aws")
        assert "check_a" in check_map
        assert "check_b" not in check_map

    def test_dict_checks_provider_not_present(self):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
        ]
        fw = _make_framework(reqs, TableConfig(group_by="Section"))
        check_map = _build_requirement_check_map(fw, provider="gcp")
        assert len(check_map) == 0


class TestGetGroupKey:
    """Test cases for resolving the group key of a requirement."""

    def test_normal_field(self):
        req = UniversalComplianceRequirement(
            id="1.1",
            description="test",
            attributes={"Section": "IAM"},
            checks={},
        )
        assert _get_group_key(req, "Section") == ["IAM"]

    def test_tactics(self):
        req = UniversalComplianceRequirement(
            id="T1190",
            description="test",
            attributes={},
            checks={},
            tactics=["Initial Access", "Execution"],
        )
        assert _get_group_key(req, "_Tactics") == ["Initial Access", "Execution"]


class TestGroupedMode:
    """Test cases for grouped-mode universal compliance table rendering."""

    def test_grouped_rendering(self, capsys, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"]},
            ),
            UniversalComplianceRequirement(
                id="2.1",
                description="test2",
                attributes={"Section": "Logging"},
                checks={"aws": ["check_b"]},
            ),
        ]
        tc = TableConfig(group_by="Section")
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
            str(tmp_path),
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        assert "IAM" in captured.out
        assert "Logging" in captured.out
        assert "PASS" in captured.out
        assert "FAIL" in captured.out

    def test_grouped_multi_section_no_undercount(self, capsys, tmp_path):
        """A single check mapped to several sections must be counted in
        every section it belongs to, not only the first one seen."""
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a", "check_b"]},
            ),
            UniversalComplianceRequirement(
                id="2.1",
                description="test2",
                attributes={"Section": "Logging"},
                checks={"aws": ["check_a"]},
            ),
        ]
        tc = TableConfig(group_by="Section")
        fw = _make_framework(reqs, tc)

        # check_a (FAIL) belongs to both IAM and Logging sections; check_b
        # (PASS, IAM only) is added so the overview total reaches 2 and the
        # results table is rendered.
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
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
            str(tmp_path),
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        plain = _strip_ansi(captured.out)
        # Both the IAM and Logging rows must report FAIL(1). Before the fix the
        # second section seen (Logging) was undercounted to FAIL(0) and rendered
        # as PASS. Anchor each occurrence to its own table row so an unrelated
        # "FAIL(1)" elsewhere cannot mask an undercount.
        iam_row = [
            line for line in plain.splitlines() if "IAM" in line and "FAIL(1)" in line
        ]
        logging_row = [
            line
            for line in plain.splitlines()
            if "Logging" in line and "FAIL(1)" in line
        ]
        assert len(iam_row) == 1
        assert len(logging_row) == 1

    def test_grouped_multi_section_muted_not_undercounted(self, capsys, tmp_path):
        """A single MUTED finding mapped to several groups must be counted in
        the per-group Muted column of every group it belongs to."""
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a", "check_b"]},
            ),
            UniversalComplianceRequirement(
                id="2.1",
                description="test2",
                attributes={"Section": "Logging"},
                checks={"aws": ["check_a"]},
            ),
        ]
        tc = TableConfig(group_by="Section")
        fw = _make_framework(reqs, tc)

        # check_a is MUTED and belongs to both IAM and Logging; check_b is a
        # plain FAIL so the overview total reaches 2 and the table is rendered.
        findings = [
            _make_finding("check_a", "FAIL", muted=True),
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
            str(tmp_path),
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        plain = _strip_ansi(captured.out)
        # The muted finding belongs to both sections, so both the IAM row and
        # the Logging row must carry a Muted count of 1 in their last cell.
        muted_one_rows = re.findall(r"│\s*1\s*│\s*$", plain, flags=re.MULTILINE)
        assert len(muted_one_rows) == 2


class TestSplitMode:
    """Test cases for split-mode universal compliance table rendering."""

    def test_split_rendering(self, capsys, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "Storage", "Profile": "Level 1"},
                checks={"aws": ["check_a"]},
            ),
            UniversalComplianceRequirement(
                id="1.2",
                description="test2",
                attributes={"Section": "Storage", "Profile": "Level 2"},
                checks={"aws": ["check_b"]},
            ),
        ]
        tc = TableConfig(
            group_by="Section",
            split_by=SplitByConfig(field="Profile", values=["Level 1", "Level 2"]),
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
            str(tmp_path),
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        assert "Storage" in captured.out
        assert "Level 1" in captured.out
        assert "Level 2" in captured.out

    def test_split_muted_multi_section_not_undercounted(self, capsys, tmp_path):
        """In split mode a single MUTED finding mapped to several groups must
        be counted in the Muted column of every group it belongs to."""
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "Storage", "Profile": "Level 1"},
                checks={"aws": ["check_a", "check_b"]},
            ),
            UniversalComplianceRequirement(
                id="2.1",
                description="test2",
                attributes={"Section": "Logging", "Profile": "Level 1"},
                checks={"aws": ["check_a"]},
            ),
        ]
        tc = TableConfig(
            group_by="Section",
            split_by=SplitByConfig(field="Profile", values=["Level 1", "Level 2"]),
        )
        fw = _make_framework(reqs, tc)

        # check_a is MUTED and belongs to both Storage and Logging; check_b is a
        # plain FAIL so the table is rendered.
        findings = [
            _make_finding("check_a", "FAIL", muted=True),
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
            str(tmp_path),
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        plain = _strip_ansi(captured.out)
        # Both section rows must carry a Muted count of 1 (last cell). Before the
        # fix only the first group seen incremented Muted, leaving the other 0.
        muted_one_rows = re.findall(r"│\s*1\s*│\s*$", plain, flags=re.MULTILINE)
        assert len(muted_one_rows) == 2

    def test_split_same_group_value_not_double_counted(self, capsys, tmp_path):
        """A single finding whose check maps to several requirements that share
        the same group and split value must count once for that group/split,
        not once per requirement (FAIL(1), never FAIL(2))."""
        reqs = [
            # check_a appears in two requirements, both Storage / Level 1.
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "Storage", "Profile": "Level 1"},
                checks={"aws": ["check_a"]},
            ),
            UniversalComplianceRequirement(
                id="1.2",
                description="test2",
                attributes={"Section": "Storage", "Profile": "Level 1"},
                checks={"aws": ["check_a"]},
            ),
            # A second group so the table renders with more than one finding.
            UniversalComplianceRequirement(
                id="2.1",
                description="test3",
                attributes={"Section": "Logging", "Profile": "Level 1"},
                checks={"aws": ["check_b"]},
            ),
        ]
        tc = TableConfig(
            group_by="Section",
            split_by=SplitByConfig(field="Profile", values=["Level 1", "Level 2"]),
        )
        fw = _make_framework(reqs, tc)

        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
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
            str(tmp_path),
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        plain = _strip_ansi(captured.out)
        # The Storage row must show FAIL(1) for Level 1, never FAIL(2).
        assert "FAIL(1)" in plain
        assert "FAIL(2)" not in plain


class TestScoredMode:
    """Test cases for scored-mode universal compliance table rendering."""

    def test_scored_rendering(self, capsys, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM", "LevelOfRisk": 5, "Weight": 100},
                checks={"aws": ["check_a"]},
            ),
            UniversalComplianceRequirement(
                id="1.2",
                description="test2",
                attributes={"Section": "IAM", "LevelOfRisk": 3, "Weight": 50},
                checks={"aws": ["check_b"]},
            ),
        ]
        tc = TableConfig(
            group_by="Section",
            scoring=ScoringConfig(risk_field="LevelOfRisk", weight_field="Weight"),
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
            str(tmp_path),
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        assert "IAM" in captured.out
        assert "Score" in captured.out
        assert "Threat Score" in captured.out

    def test_scored_multi_section_fail_not_undercounted(self, capsys, tmp_path):
        """In scored mode a single FAIL finding mapped to several groups must
        show FAIL(1) in every group it belongs to, not only the first one."""
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM", "LevelOfRisk": 5, "Weight": 100},
                checks={"aws": ["check_a", "check_b"]},
            ),
            UniversalComplianceRequirement(
                id="2.1",
                description="test2",
                attributes={"Section": "Logging", "LevelOfRisk": 3, "Weight": 50},
                checks={"aws": ["check_a"]},
            ),
        ]
        tc = TableConfig(
            group_by="Section",
            scoring=ScoringConfig(risk_field="LevelOfRisk", weight_field="Weight"),
        )
        fw = _make_framework(reqs, tc)

        # check_a (FAIL) belongs to both IAM and Logging; check_b (PASS, IAM
        # only) raises the overview total to 2 so the table is rendered.
        findings = [
            _make_finding("check_a", "FAIL"),
            _make_finding("check_b", "PASS"),
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
            str(tmp_path),
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        plain = _strip_ansi(captured.out)
        iam_row = [
            line for line in plain.splitlines() if "IAM" in line and "FAIL(1)" in line
        ]
        logging_row = [
            line
            for line in plain.splitlines()
            if "Logging" in line and "FAIL(1)" in line
        ]
        assert len(iam_row) == 1
        assert len(logging_row) == 1


class TestCustomLabels:
    """Test cases for custom-label universal compliance table rendering."""

    def test_ens_spanish_labels(self, capsys, tmp_path):
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Marco": "operacional"},
                checks={"aws": ["check_a"]},
            ),
            UniversalComplianceRequirement(
                id="1.2",
                description="test2",
                attributes={"Marco": "organizativo"},
                checks={"aws": ["check_b"]},
            ),
        ]
        tc = TableConfig(
            group_by="Marco",
            labels=TableLabels(
                pass_label="CUMPLE",
                fail_label="NO CUMPLE",
                provider_header="Proveedor",
                title="Estado de Cumplimiento",
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
            str(tmp_path),
            False,
            framework=fw,
        )

        captured = capsys.readouterr()
        assert "CUMPLE" in captured.out
        assert "Estado de Cumplimiento" in captured.out


class TestMultiProviderDictChecks:
    """Test cases for multi-provider dict checks in the universal table."""

    def test_only_aws_checks_matched(self, capsys, tmp_path):
        """With dict checks and provider='aws', only AWS checks match findings."""
        reqs = [
            UniversalComplianceRequirement(
                id="1.1",
                description="test",
                attributes={"Section": "IAM"},
                checks={"aws": ["check_a"], "azure": ["check_b"]},
            ),
            UniversalComplianceRequirement(
                id="2.1",
                description="test2",
                attributes={"Section": "Logging"},
                checks={"aws": ["check_c"], "gcp": ["check_d"]},
            ),
        ]
        tc = TableConfig(group_by="Section")
        fw = ComplianceFramework(
            framework="MultiCloud",
            name="Multi",
            description="Test",
            requirements=reqs,
            outputs=OutputsConfig(table_config=tc),
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
            str(tmp_path),
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
    """Test cases for the universal table when no table config is present."""

    def test_returns_early_without_table_config(self, capsys, tmp_path):
        fw = ComplianceFramework(
            framework="TestFW",
            name="Test",
            provider="AWS",
            description="Test",
            requirements=[],
        )
        get_universal_table([], {}, "test", "out", str(tmp_path), False, framework=fw)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_returns_early_without_framework(self, capsys, tmp_path):
        get_universal_table([], {}, "test", "out", str(tmp_path), False, framework=None)
        captured = capsys.readouterr()
        assert captured.out == ""
