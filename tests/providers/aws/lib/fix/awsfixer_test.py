import json
from unittest.mock import MagicMock, patch

from prowler.lib.check.models import (
    Check_Report_AWS,
    CheckMetadata,
    Code,
    Recommendation,
    Remediation,
)
from prowler.providers.aws.lib.fix.fixer import AWSFixer


def get_mock_aws_finding():
    metadata = CheckMetadata(
        Provider="aws",
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
    resource = MagicMock()
    resource.id = "res_id"
    resource.arn = "arn:aws:test"
    resource.region = "eu-west-1"
    return Check_Report_AWS(json.dumps(metadata.dict()), resource)


class TestAWSFixer:
    def test_fix_success(self):
        finding = get_mock_aws_finding()
        finding.status = "FAIL"
        with patch("prowler.providers.aws.lib.fix.fixer.AWSFixer.client"):
            fixer = AWSFixer(description="desc", service="ec2")
            assert fixer.fix(finding=finding)

    def test_fix_failure(self, caplog):
        fixer = AWSFixer(description="desc", service="ec2")
        with patch("prowler.providers.aws.lib.fix.fixer.logger") as mock_logger:
            with caplog.at_level("ERROR"):
                result = fixer.fix(finding=None)
                assert result is False
                assert mock_logger.error.called

    def test_get_fixer_info(self):
        fixer = AWSFixer(
            description="desc",
            service="ec2",
            cost_impact=True,
            cost_description="cost",
            iam_policy_required={"Action": ["ec2:DescribeInstances"]},
        )
        info = fixer._get_fixer_info()
        assert info["description"] == "desc"
        assert info["cost_impact"] is True
        assert info["cost_description"] == "cost"
        assert info["service"] == "ec2"
        assert info["iam_policy_required"] == {"Action": ["ec2:DescribeInstances"]}

    def test_fix_prints(self):
        fixer = AWSFixer(description="desc", service="ec2")
        finding = get_mock_aws_finding()
        finding.region = "eu-west-1"
        finding.resource_id = "res_id"
        finding.resource_arn = "arn:aws:test"
        with (
            patch("builtins.print") as mock_print,
            patch("prowler.providers.aws.lib.fix.fixer.logger") as mock_logger,
        ):
            result = fixer.fix(finding=finding)
            if (
                finding.region
                or finding.resource_id
                or getattr(finding, "resource_arn", None)
            ):
                assert result is True
                assert mock_print.called
            else:
                assert result is False
                assert mock_logger.error.called

    def test_fix_exception(self):
        fixer = AWSFixer(description="desc", service="ec2")
        with patch("prowler.providers.aws.lib.fix.fixer.logger") as mock_logger:
            result = fixer.fix(finding=None)
            assert result is False
            assert mock_logger.error.called
