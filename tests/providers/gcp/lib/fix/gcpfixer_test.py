from unittest.mock import patch

from prowler.lib.check.models import (
    Check_Report_GCP,
    CheckMetadata,
    Code,
    Recommendation,
    Remediation,
)
from prowler.providers.gcp.lib.fix.fixer import GCPFixer


def get_mock_gcp_finding():
    metadata = CheckMetadata(
        Provider="gcp",
        CheckID="test_check",
        CheckTitle="Test Check",
        CheckType=["type1"],
        CheckAliases=[],
        ServiceName="testservice",
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
    return Check_Report_GCP(
        metadata.dict(),
        project_id="project_id",
        resource_id="resource_id",
        resource_name="resource_name",
        location="location",
    )


class TestGCPFixer:
    def test_fix_success(self):
        finding = get_mock_gcp_finding()
        finding.status = "FAIL"
        fixer = GCPFixer(description="desc", service="compute")
        assert fixer.fix(finding=finding)

    def test_fix_failure(self, caplog):
        finding = get_mock_gcp_finding()
        finding.status = "FAIL"
        fixer = GCPFixer(description="desc", service="compute")
        with patch("prowler.providers.gcp.lib.fix.fixer.logger") as mock_logger:
            with caplog.at_level("ERROR"):
                result = fixer.fix(finding=None)
                assert result is False
                assert mock_logger.error.called

    def test_get_fixer_info(self):
        fixer = GCPFixer(
            description="desc",
            service="compute",
            cost_impact=True,
            cost_description="cost",
            iam_policy_required={"roles": ["roles/owner"]},
        )
        info = fixer._get_fixer_info()
        assert info["description"] == "desc"
        assert info["cost_impact"] is True
        assert info["cost_description"] == "cost"
        assert info["service"] == "compute"
        assert info["iam_policy_required"] == {"roles": ["roles/owner"]}
        assert info["provider"] == "gcp"

    def test_fix_prints(self):
        fixer = GCPFixer(description="desc", service="compute")
        finding = get_mock_gcp_finding()
        with (
            patch("builtins.print") as mock_print,
            patch("prowler.providers.gcp.lib.fix.fixer.logger"),
        ):
            result = fixer.fix(finding=finding)
            assert result is True
            mock_print.assert_called_once_with(
                f"\tFIXING {finding.resource_id} in project {finding.project_id}..."
            )

    def test_fix_exception(self):
        fixer = GCPFixer(description="desc", service="compute")
        with patch("prowler.providers.gcp.lib.fix.fixer.logger") as mock_logger:
            result = fixer.fix(finding=None)
            assert result is False
            assert mock_logger.error.called
