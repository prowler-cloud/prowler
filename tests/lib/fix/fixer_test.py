import json
from unittest.mock import MagicMock, patch

import pytest

from prowler.lib.check.models import (
    Check_Report,
    CheckMetadata,
    Code,
    Recommendation,
    Remediation,
)
from prowler.lib.fix.fixer import Fixer


def get_mock_metadata(
    provider="aws", check_id="test_check", service_name="testservice"
):
    return CheckMetadata(
        Provider=provider,
        CheckID=check_id,
        CheckTitle="Test Check",
        CheckType=["type1"],
        CheckAliases=[],
        ServiceName=service_name,
        SubServiceName="",
        ResourceIdTemplate="",
        Severity="low",
        ResourceType="resource",
        Description="desc",
        Risk="risk",
        RelatedUrl="url",
        Remediation=Remediation(
            Code=Code(NativeIaC="", Terraform="", CLI="", Other=""),
            Recommendation=Recommendation(Text="", Url=""),
        ),
        Categories=["cat1"],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=[],
    )


def build_metadata(provider="aws", check_id="test_check", service_name="testservice"):
    return CheckMetadata(
        Provider=provider,
        CheckID=check_id,
        CheckTitle="Test Check",
        CheckType=["type1"],
        CheckAliases=[],
        ServiceName=service_name,
        SubServiceName="",
        ResourceIdTemplate="",
        Severity="low",
        ResourceType="resource",
        Description="desc",
        Risk="risk",
        RelatedUrl="url",
        Remediation=Remediation(
            Code=Code(NativeIaC="", Terraform="", CLI="", Other=""),
            Recommendation=Recommendation(Text="", Url=""),
        ),
        Categories=["cat1"],
        DependsOn=[],
        RelatedTo=[],
        Notes="",
        Compliance=[],
    )


def build_finding(
    status="FAIL", provider="aws", check_id="test_check", service_name="testservice"
):
    metadata = build_metadata(provider, check_id, service_name)
    resource = MagicMock()
    finding = Check_Report(json.dumps(metadata.dict()), resource)
    finding.status = status
    return finding


class DummyFixer(Fixer):
    def fix(self, finding=None, **kwargs):
        return True


class TestFixer:
    def test_get_fixer_info(self):
        fixer = DummyFixer(
            description="desc", cost_impact=True, cost_description="cost"
        )
        info = fixer._get_fixer_info()
        assert info == {
            "description": "desc",
            "cost_impact": True,
            "cost_description": "cost",
        }

    def test_client_property(self):
        fixer = DummyFixer(description="desc")
        assert fixer.client is None

    @pytest.mark.parametrize(
        "check_id,provider,service_name,expected_class",
        [
            (None, "aws", "testservice", None),
            ("test_check", None, "testservice", None),
            ("nonexistent_check", "aws", "testservice", None),
        ],
    )
    def test_get_fixer_for_finding_edge(
        self, check_id, provider, service_name, expected_class
    ):
        finding = MagicMock()
        finding.check_metadata.CheckID = check_id
        finding.check_metadata.Provider = provider
        finding.check_metadata.ServiceName = service_name
        with patch("prowler.lib.fix.fixer.logger"):
            fixer = Fixer.get_fixer_for_finding(finding)
            assert fixer is expected_class

    def test_get_fixer_for_finding_importerror_print(self):
        finding = MagicMock()
        finding.check_metadata.CheckID = "nonexistent_check"
        finding.check_metadata.Provider = "aws"
        finding.check_metadata.ServiceName = "testservice"
        with patch("builtins.print") as mock_print:
            fixer = Fixer.get_fixer_for_finding(finding)
            assert fixer is None
            assert mock_print.called

    def test_run_fixer_single_and_multiple(self):
        finding = build_finding(status="FAIL")
        with patch.object(Fixer, "run_individual_fixer", return_value=1) as mock_run:
            assert Fixer.run_fixer(finding) == 1
            assert mock_run.called
        finding.status = "PASS"
        assert Fixer.run_fixer(finding) == 0
        finding1 = build_finding(status="FAIL")
        finding2 = build_finding(status="FAIL")
        with patch.object(Fixer, "run_individual_fixer", return_value=2) as mock_run:
            assert Fixer.run_fixer([finding1, finding2]) == 2
            assert mock_run.called

    def test_run_fixer_grouping(self):
        finding1 = build_finding(status="FAIL", check_id="check1")
        finding2 = build_finding(status="FAIL", check_id="check1")
        finding3 = build_finding(status="FAIL", check_id="check2")
        calls = {}

        def fake_run_individual_fixer(check_id, findings):
            calls[check_id] = len(findings)
            return len(findings)

        with patch.object(
            Fixer, "run_individual_fixer", side_effect=fake_run_individual_fixer
        ):
            total = Fixer.run_fixer([finding1, finding2, finding3])
            assert total == 3
            assert calls == {"check1": 2, "check2": 1}

    def test_run_fixer_exception(self):
        finding = build_finding(status="FAIL")
        with patch.object(Fixer, "run_individual_fixer", side_effect=Exception("fail")):
            with patch("prowler.lib.fix.fixer.logger") as mock_logger:
                assert Fixer.run_fixer(finding) == 0
                assert mock_logger.error.called

    def test_run_individual_fixer_success(self):
        finding = build_finding(status="FAIL")
        with (
            patch.object(Fixer, "get_fixer_for_finding") as mock_factory,
            patch("builtins.print") as mock_print,
        ):
            fixer = DummyFixer(description="desc")
            mock_factory.return_value = fixer
            with patch.object(fixer, "fix", return_value=True):
                total = Fixer.run_individual_fixer("test_check", [finding])
                assert total == 1
                assert mock_print.call_count > 0

    def test_run_individual_fixer_no_fixer(self):
        finding = build_finding(status="FAIL")
        with patch.object(Fixer, "get_fixer_for_finding", return_value=None):
            assert Fixer.run_individual_fixer("test_check", [finding]) == 0

    def test_run_individual_fixer_fix_error(self):
        finding = build_finding(status="FAIL")
        with (
            patch.object(Fixer, "get_fixer_for_finding") as mock_factory,
            patch("builtins.print") as mock_print,
        ):
            fixer = DummyFixer(description="desc")
            mock_factory.return_value = fixer
            with patch.object(fixer, "fix", return_value=False):
                total = Fixer.run_individual_fixer("test_check", [finding])
                assert total == 0
                assert mock_print.call_count > 0

    def test_run_individual_fixer_exception(self):
        finding = build_finding(status="FAIL")
        with patch.object(
            Fixer, "get_fixer_for_finding", side_effect=Exception("fail")
        ):
            with patch("prowler.lib.fix.fixer.logger") as mock_logger:
                assert Fixer.run_individual_fixer("test_check", [finding]) == 0
                assert mock_logger.error.called
