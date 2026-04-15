from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.ccc.ccc_azure import CCC_Azure
from prowler.lib.outputs.compliance.ccc.models import CCC_AzureModel
from tests.lib.outputs.compliance.fixtures import CCC_AZURE_FIXTURE
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION_ID

AZURE_LOCATION = "westeurope"


class TestAzureCCC:
    def test_output_transform_evaluated_requirement(self):
        findings = [
            generate_finding_output(
                provider="azure",
                compliance={"CCC-v2025.10": "CCC.Core.CN01.AR01"},
                account_uid=AZURE_SUBSCRIPTION_ID,
                region=AZURE_LOCATION,
            )
        ]

        output = CCC_Azure(findings, CCC_AZURE_FIXTURE)
        output_data = output.data[0]

        assert isinstance(output_data, CCC_AzureModel)
        assert output_data.Provider == "azure"
        assert output_data.SubscriptionId == AZURE_SUBSCRIPTION_ID
        assert output_data.Location == AZURE_LOCATION
        assert output_data.Description == CCC_AZURE_FIXTURE.Description
        assert output_data.Requirements_Id == CCC_AZURE_FIXTURE.Requirements[0].Id
        attribute = CCC_AZURE_FIXTURE.Requirements[0].Attributes[0]
        assert output_data.Requirements_Attributes_FamilyName == attribute.FamilyName
        assert output_data.Requirements_Attributes_Section == attribute.Section
        assert (
            output_data.Requirements_Attributes_Applicability == attribute.Applicability
        )
        assert output_data.Status == "PASS"
        assert output_data.CheckId == "service_test_check_id"

    def test_output_transform_manual_requirement(self):
        findings = [
            generate_finding_output(
                provider="azure",
                compliance={"CCC-v2025.10": "CCC.Core.CN01.AR01"},
                account_uid=AZURE_SUBSCRIPTION_ID,
                region=AZURE_LOCATION,
            )
        ]
        output = CCC_Azure(findings, CCC_AZURE_FIXTURE)
        manual_row = output.data[1]

        assert isinstance(manual_row, CCC_AzureModel)
        assert manual_row.Provider == "azure"
        assert manual_row.SubscriptionId == ""
        assert manual_row.Location == ""
        assert manual_row.Requirements_Id == CCC_AZURE_FIXTURE.Requirements[1].Id
        assert manual_row.Status == "MANUAL"
        assert manual_row.CheckId == "manual"

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.ccc.ccc_azure.timestamp",
        "2025-01-01 00:00:00",
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                provider="azure",
                compliance={"CCC-v2025.10": "CCC.Core.CN01.AR01"},
                account_uid=AZURE_SUBSCRIPTION_ID,
                region=AZURE_LOCATION,
            )
        ]
        output = CCC_Azure(findings, CCC_AZURE_FIXTURE)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        header = content.split("\r\n", 1)[0]
        assert "SUBSCRIPTIONID" in header
        assert "LOCATION" in header
        assert "ACCOUNTID" not in header
        assert "PROJECTID" not in header
        assert "REGION" not in header
        rows = [r for r in content.split("\r\n") if r]
        assert len(rows) == 3
        assert "CCC.Core.CN01.AR01" in rows[1]
        assert AZURE_SUBSCRIPTION_ID in rows[1]
        assert "CCC.IAM.CN01.AR01" in rows[2]
        assert "MANUAL" in rows[2]
