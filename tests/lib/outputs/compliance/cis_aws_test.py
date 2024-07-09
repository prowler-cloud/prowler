from io import StringIO

from mock import patch

from prowler.lib.outputs.compliance.cis_aws import AWSCIS
from prowler.lib.outputs.compliance.models import AWS
from tests.lib.outputs.compliance.fixtures import CIS_1_4_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestAWSCIS:
    def test_output_transform(self):
        findings = [generate_finding_output(compliance={"CIS-1.4": "2.1.3"})]

        output = AWSCIS(findings, CIS_1_4_AWS)
        output_data = output.data[0]
        assert isinstance(output_data, AWS)
        assert output_data.Provider == "aws"
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Description == CIS_1_4_AWS.Description
        assert output_data.Requirements_Id == CIS_1_4_AWS.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == CIS_1_4_AWS.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Section
            == CIS_1_4_AWS.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_Profile
            == CIS_1_4_AWS.Requirements[0].Attributes[0].Profile
        )
        assert (
            output_data.Requirements_Attributes_AssessmentStatus
            == CIS_1_4_AWS.Requirements[0].Attributes[0].AssessmentStatus
        )
        assert (
            output_data.Requirements_Attributes_Description
            == CIS_1_4_AWS.Requirements[0].Attributes[0].Description
        )
        assert (
            output_data.Requirements_Attributes_RationaleStatement
            == CIS_1_4_AWS.Requirements[0].Attributes[0].RationaleStatement
        )
        assert (
            output_data.Requirements_Attributes_ImpactStatement
            == CIS_1_4_AWS.Requirements[0].Attributes[0].ImpactStatement
        )
        assert (
            output_data.Requirements_Attributes_RemediationProcedure
            == CIS_1_4_AWS.Requirements[0].Attributes[0].RemediationProcedure
        )
        assert (
            output_data.Requirements_Attributes_AuditProcedure
            == CIS_1_4_AWS.Requirements[0].Attributes[0].AuditProcedure
        )
        assert (
            output_data.Requirements_Attributes_AdditionalInformation
            == CIS_1_4_AWS.Requirements[0].Attributes[0].AdditionalInformation
        )
        assert (
            output_data.Requirements_Attributes_References
            == CIS_1_4_AWS.Requirements[0].Attributes[0].References
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.CheckId == "test-check-id"
        assert output_data.Muted is False

    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [generate_finding_output(compliance={"CIS-1.4": "2.1.3"})]
        # Clear the data from CSV class
        output = AWSCIS(findings, CIS_1_4_AWS)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        assert CIS_1_4_AWS.Description in content
