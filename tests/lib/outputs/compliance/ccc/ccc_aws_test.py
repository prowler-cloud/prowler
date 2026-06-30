from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.ccc.ccc_aws import CCC_AWS
from prowler.lib.outputs.compliance.ccc.models import CCC_AWSModel
from tests.lib.outputs.compliance.fixtures import CCC_AWS_FIXTURE
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestAWSCCC:
    def test_output_transform_evaluated_requirement(self):
        findings = [
            generate_finding_output(compliance={"CCC-v2025.10": "CCC.Core.CN01.AR01"})
        ]

        output = CCC_AWS(findings, CCC_AWS_FIXTURE)
        output_data = output.data[0]

        assert isinstance(output_data, CCC_AWSModel)
        assert output_data.Provider == "aws"
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Description == CCC_AWS_FIXTURE.Description
        assert output_data.Requirements_Id == CCC_AWS_FIXTURE.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == CCC_AWS_FIXTURE.Requirements[0].Description
        )
        attribute = CCC_AWS_FIXTURE.Requirements[0].Attributes[0]
        assert output_data.Requirements_Attributes_FamilyName == attribute.FamilyName
        assert (
            output_data.Requirements_Attributes_FamilyDescription
            == attribute.FamilyDescription
        )
        assert output_data.Requirements_Attributes_Section == attribute.Section
        assert output_data.Requirements_Attributes_SubSection == attribute.SubSection
        assert (
            output_data.Requirements_Attributes_SubSectionObjective
            == attribute.SubSectionObjective
        )
        assert (
            output_data.Requirements_Attributes_Applicability == attribute.Applicability
        )
        assert (
            output_data.Requirements_Attributes_Recommendation
            == attribute.Recommendation
        )
        assert (
            output_data.Requirements_Attributes_SectionThreatMappings
            == attribute.SectionThreatMappings
        )
        assert (
            output_data.Requirements_Attributes_SectionGuidelineMappings
            == attribute.SectionGuidelineMappings
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "service_test_check_id"
        assert output_data.Muted is False

    def test_output_transform_manual_requirement(self):
        # Use a finding for the evaluated requirement so the manual one is appended
        # by the manual-loop branch (Checks=[]).
        findings = [
            generate_finding_output(compliance={"CCC-v2025.10": "CCC.Core.CN01.AR01"})
        ]

        output = CCC_AWS(findings, CCC_AWS_FIXTURE)
        # data[0] is the evaluated PASS row, data[1] is the manual row
        manual_row = output.data[1]

        assert isinstance(manual_row, CCC_AWSModel)
        assert manual_row.Provider == "aws"
        assert manual_row.AccountId == ""
        assert manual_row.Region == ""
        assert manual_row.Description == CCC_AWS_FIXTURE.Description
        assert manual_row.Requirements_Id == CCC_AWS_FIXTURE.Requirements[1].Id
        manual_attribute = CCC_AWS_FIXTURE.Requirements[1].Attributes[0]
        assert (
            manual_row.Requirements_Attributes_FamilyName == manual_attribute.FamilyName
        )
        assert manual_row.Requirements_Attributes_Section == manual_attribute.Section
        assert manual_row.Status == "MANUAL"
        assert manual_row.StatusExtended == "Manual check"
        assert manual_row.ResourceId == "manual_check"
        assert manual_row.ResourceName == "Manual check"
        assert manual_row.CheckId == "manual"
        assert manual_row.Muted is False

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.ccc.ccc_aws.timestamp",
        "2025-01-01 00:00:00",
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(compliance={"CCC-v2025.10": "CCC.Core.CN01.AR01"})
        ]
        output = CCC_AWS(findings, CCC_AWS_FIXTURE)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()

        # Header check: AWS-specific columns must be present
        header = content.split("\r\n", 1)[0]
        assert "ACCOUNTID" in header
        assert "REGION" in header
        assert "REQUIREMENTS_ATTRIBUTES_FAMILYNAME" in header
        assert "REQUIREMENTS_ATTRIBUTES_SECTION" in header
        assert "REQUIREMENTS_ATTRIBUTES_APPLICABILITY" in header
        assert "REQUIREMENTS_ATTRIBUTES_SECTIONTHREATMAPPINGS" in header
        # Header should NOT contain Azure or GCP-only columns
        assert "SUBSCRIPTIONID" not in header
        assert "PROJECTID" not in header

        # Body checks: evaluated row + manual row
        rows = [r for r in content.split("\r\n") if r]
        assert len(rows) == 3  # header + evaluated + manual
        assert "CCC.Core.CN01.AR01" in rows[1]
        assert "PASS" in rows[1]
        assert AWS_ACCOUNT_NUMBER in rows[1]
        assert AWS_REGION_EU_WEST_1 in rows[1]
        assert "CCC.IAM.CN01.AR01" in rows[2]
        assert "MANUAL" in rows[2]
        assert "manual_check" in rows[2]
        # The frozen timestamp should appear
        assert "2025-01-01 00:00:00" in rows[1]
