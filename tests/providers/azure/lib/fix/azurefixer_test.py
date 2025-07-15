import json
from unittest.mock import MagicMock, patch

from prowler.lib.check.models import (
    Check_Report_Azure,
    CheckMetadata,
    Code,
    Recommendation,
    Remediation,
)
from prowler.providers.azure.lib.fix.fixer import AzureFixer


def get_mock_azure_finding():
    metadata = CheckMetadata(
        Provider="azure",
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
    resource.name = "res_name"
    resource.id = "res_id"
    resource.location = "westeurope"
    return Check_Report_Azure(json.dumps(metadata.dict()), resource)


class TestAzureFixer:
    def test_fix_success(self):
        finding = get_mock_azure_finding()
        finding.status = "FAIL"
        with patch("prowler.providers.azure.lib.fix.fixer.AzureFixer.client"):
            fixer = AzureFixer(description="desc", service="vm")
            assert fixer.fix(finding=finding)

    def test_fix_failure(self, caplog):
        finding = get_mock_azure_finding()
        finding.status = "FAIL"
        fixer = AzureFixer(description="desc", service="vm")
        with patch("prowler.providers.azure.lib.fix.fixer.logger") as mock_logger:
            with caplog.at_level("ERROR"):
                result = fixer.fix(finding=None)
                assert result is False
                assert mock_logger.error.called

    def test_get_fixer_info(self):
        fixer = AzureFixer(
            description="desc",
            service="vm",
            cost_impact=True,
            cost_description="cost",
            permissions_required={"Action": ["Microsoft.Compute/virtualMachines/read"]},
        )
        info = fixer._get_fixer_info()
        assert info["description"] == "desc"
        assert info["cost_impact"] is True
        assert info["cost_description"] == "cost"
        assert info["service"] == "vm"
        assert info["permissions_required"] == {
            "Action": ["Microsoft.Compute/virtualMachines/read"]
        }

    def test_fix_prints(self):
        fixer = AzureFixer(description="desc", service="vm")
        finding = get_mock_azure_finding()
        finding.subscription = "subid"
        finding.resource_id = "res_id"
        finding.resource = {"resource_group_name": "rg1"}
        with (
            patch("builtins.print") as mock_print,
            patch("prowler.providers.azure.lib.fix.fixer.logger"),
        ):
            result = fixer.fix(finding=finding)
            assert result is True
            assert mock_print.called

    def test_fix_exception(self):
        fixer = AzureFixer(description="desc", service="vm")
        with patch("prowler.providers.azure.lib.fix.fixer.logger") as mock_logger:
            result = fixer.fix(finding=None)
            assert result is False
            assert mock_logger.error.called
