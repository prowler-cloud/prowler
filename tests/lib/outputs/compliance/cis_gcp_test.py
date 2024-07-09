from io import StringIO

from mock import patch

from prowler.lib.outputs.compliance.cis_gcp import GCPCIS
from prowler.lib.outputs.compliance.models import GCP
from tests.lib.outputs.compliance.fixtures import CIS_2_0_GCP
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID


class TestGCPCIS:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                provider="gcp",
                compliance={"CIS-2.0": "2.13"},
                account_name=GCP_PROJECT_ID,
                account_uid=GCP_PROJECT_ID,
                region="",
            )
        ]

        output = GCPCIS(findings, CIS_2_0_GCP)
        output_data = output.data[0]
        assert isinstance(output_data, GCP)
        assert output_data.Provider == "gcp"
        assert output_data.ProjectId == GCP_PROJECT_ID
        assert output_data.Location == ""
        assert output_data.Description == CIS_2_0_GCP.Description
        assert output_data.Requirements_Id == CIS_2_0_GCP.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == CIS_2_0_GCP.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Section
            == CIS_2_0_GCP.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_Profile
            == CIS_2_0_GCP.Requirements[0].Attributes[0].Profile
        )
        assert (
            output_data.Requirements_Attributes_AssessmentStatus
            == CIS_2_0_GCP.Requirements[0].Attributes[0].AssessmentStatus
        )
        assert (
            output_data.Requirements_Attributes_Description
            == CIS_2_0_GCP.Requirements[0].Attributes[0].Description
        )
        assert (
            output_data.Requirements_Attributes_RationaleStatement
            == CIS_2_0_GCP.Requirements[0].Attributes[0].RationaleStatement
        )
        assert (
            output_data.Requirements_Attributes_ImpactStatement
            == CIS_2_0_GCP.Requirements[0].Attributes[0].ImpactStatement
        )
        assert (
            output_data.Requirements_Attributes_RemediationProcedure
            == CIS_2_0_GCP.Requirements[0].Attributes[0].RemediationProcedure
        )
        assert (
            output_data.Requirements_Attributes_AuditProcedure
            == CIS_2_0_GCP.Requirements[0].Attributes[0].AuditProcedure
        )
        assert (
            output_data.Requirements_Attributes_AdditionalInformation
            == CIS_2_0_GCP.Requirements[0].Attributes[0].AdditionalInformation
        )
        assert (
            output_data.Requirements_Attributes_References
            == CIS_2_0_GCP.Requirements[0].Attributes[0].References
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.CheckId == "test-check-id"
        assert output_data.Muted is False

    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [generate_finding_output(compliance={"CIS-2.0": "2.13"})]
        # Clear the data from CSV class
        output = GCPCIS(findings, CIS_2_0_GCP)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        assert CIS_2_0_GCP.Description in content
