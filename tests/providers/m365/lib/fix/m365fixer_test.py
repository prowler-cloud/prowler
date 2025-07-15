import json
from unittest.mock import MagicMock, patch

import pytest

from prowler.lib.check.models import (
    CheckMetadata,
    CheckReportM365,
    Code,
    Recommendation,
    Remediation,
    Severity,
)
from prowler.providers.m365.lib.fix.fixer import M365Fixer


def get_mock_m365_finding():
    metadata = CheckMetadata(
        Provider="m365",
        CheckID="test_check",
        CheckTitle="Test Check",
        CheckType=["type1"],
        CheckAliases=[],
        ServiceName="testservice",
        SubServiceName="",
        ResourceIdTemplate="",
        Severity=Severity.low,
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
    resource.location = "global"
    return CheckReportM365(
        json.dumps(metadata.dict()),
        resource,
        resource_name="res_name",
        resource_id="res_id",
    )


class TestM365Fixer:
    def test_fix_success(self):
        finding = get_mock_m365_finding()
        finding.status = "FAIL"
        with patch("prowler.providers.m365.lib.fix.fixer.M365Fixer.client"):
            fixer = M365Fixer(description="desc", service="mail")
            assert fixer.fix(finding=finding)

    def test_get_fixer_info(self):
        fixer = M365Fixer(
            description="desc",
            service="mail",
            cost_impact=True,
            cost_description="cost",
        )
        info = fixer._get_fixer_info()
        assert info["description"] == "desc"
        assert info["cost_impact"] is True
        assert info["cost_description"] == "cost"
        assert info["service"] == "mail"

    @pytest.mark.parametrize("resource_id", ["res_id", None])
    def test_fix_prints(self, resource_id):
        fixer = M365Fixer(description="desc", service="mail")
        finding = get_mock_m365_finding()
        finding.resource_id = resource_id
        with (
            patch("builtins.print") as mock_print,
            patch("prowler.providers.m365.lib.fix.fixer.logger"),
        ):
            result = fixer.fix(finding=finding)
            assert result is True
            assert mock_print.called
