from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.ccc.ccc_gcp import CCC_GCP
from prowler.lib.outputs.compliance.ccc.models import CCC_GCPModel
from tests.lib.outputs.compliance.fixtures import CCC_GCP_FIXTURE
from tests.lib.outputs.fixtures.fixtures import generate_finding_output

GCP_PROJECT_ID = "test-project"
GCP_LOCATION = "europe-west1"


class TestGCPCCC:
    def test_output_transform_evaluated_requirement(self):
        findings = [
            generate_finding_output(
                provider="gcp",
                compliance={"CCC-v2025.10": "CCC.Core.CN01.AR01"},
                account_uid=GCP_PROJECT_ID,
                region=GCP_LOCATION,
            )
        ]

        output = CCC_GCP(findings, CCC_GCP_FIXTURE)
        output_data = output.data[0]

        assert isinstance(output_data, CCC_GCPModel)
        assert output_data.Provider == "gcp"
        assert output_data.ProjectId == GCP_PROJECT_ID
        assert output_data.Location == GCP_LOCATION
        assert output_data.Description == CCC_GCP_FIXTURE.Description
        assert output_data.Requirements_Id == CCC_GCP_FIXTURE.Requirements[0].Id
        attribute = CCC_GCP_FIXTURE.Requirements[0].Attributes[0]
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
                provider="gcp",
                compliance={"CCC-v2025.10": "CCC.Core.CN01.AR01"},
                account_uid=GCP_PROJECT_ID,
                region=GCP_LOCATION,
            )
        ]
        output = CCC_GCP(findings, CCC_GCP_FIXTURE)
        manual_row = output.data[1]

        assert isinstance(manual_row, CCC_GCPModel)
        assert manual_row.Provider == "gcp"
        assert manual_row.ProjectId == ""
        assert manual_row.Location == ""
        assert manual_row.Requirements_Id == CCC_GCP_FIXTURE.Requirements[1].Id
        assert manual_row.Status == "MANUAL"
        assert manual_row.CheckId == "manual"

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.ccc.ccc_gcp.timestamp",
        "2025-01-01 00:00:00",
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                provider="gcp",
                compliance={"CCC-v2025.10": "CCC.Core.CN01.AR01"},
                account_uid=GCP_PROJECT_ID,
                region=GCP_LOCATION,
            )
        ]
        output = CCC_GCP(findings, CCC_GCP_FIXTURE)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        header = content.split("\r\n", 1)[0]
        assert "PROJECTID" in header
        assert "LOCATION" in header
        assert "ACCOUNTID" not in header
        assert "SUBSCRIPTIONID" not in header
        assert "REGION" not in header
        rows = [r for r in content.split("\r\n") if r]
        assert len(rows) == 3
        assert "CCC.Core.CN01.AR01" in rows[1]
        assert GCP_PROJECT_ID in rows[1]
        assert "CCC.IAM.CN01.AR01" in rows[2]
        assert "MANUAL" in rows[2]
