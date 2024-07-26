from datetime import datetime
from io import StringIO

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.compliance.generic.models import GenericComplianceModel
from tests.lib.outputs.compliance.fixtures import NIST_800_53_REVISION_4_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestAWSGenericCompliance:
    def test_output_transform(self):
        findings = [
            generate_finding_output(compliance={"NIST-800-53-Revision-4": "ac_2_4"})
        ]

        output = GenericCompliance(findings, NIST_800_53_REVISION_4_AWS)
        output_data = output.data[0]
        assert isinstance(output_data, GenericComplianceModel)
        assert output_data.Provider == "aws"
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Description == NIST_800_53_REVISION_4_AWS.Description
        assert (
            output_data.Requirements_Id == NIST_800_53_REVISION_4_AWS.Requirements[0].Id
        )
        assert (
            output_data.Requirements_Description
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Section
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_SubSection
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].SubSection
        )
        assert (
            output_data.Requirements_Attributes_SubGroup
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].SubGroup
        )
        assert (
            output_data.Requirements_Attributes_Service
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].Service
        )
        assert (
            output_data.Requirements_Attributes_Type
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].Type
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "test-check-id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "aws"
        assert output_data_manual.AccountId == ""
        assert output_data_manual.Region == ""
        assert output_data_manual.Description == NIST_800_53_REVISION_4_AWS.Description
        assert (
            output_data_manual.Requirements_Id
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Id
        )
        assert (
            output_data_manual.Requirements_Description
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_SubSection
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].SubSection
        )
        assert (
            output_data_manual.Requirements_Attributes_SubGroup
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].SubGroup
        )
        assert (
            output_data_manual.Requirements_Attributes_Service
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].Service
        )
        assert (
            output_data_manual.Requirements_Attributes_Type
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].Type
        )
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert output_data_manual.Muted is False

    @freeze_time(datetime.now())
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(compliance={"NIST-800-53-Revision-4": "ac_2_4"})
        ]
        output = GenericCompliance(findings, NIST_800_53_REVISION_4_AWS)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;ACCOUNTID;REGION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_SUBSECTION;REQUIREMENTS_ATTRIBUTES_SUBGROUP;REQUIREMENTS_ATTRIBUTES_SERVICE;REQUIREMENTS_ATTRIBUTES_TYPE;STATUS;STATUSEXTENDED;RESOURCEID;CHECKID;MUTED;RESOURCENAME\r\naws;NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.;123456789012;eu-west-1;{datetime.now()};ac_2_4;Account Management;Access Control (AC);Account Management (AC-2);;aws;;PASS;;;test-check-id;False;\r\naws;NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.;;;{datetime.now()};ac_2_5;Account Management;Access Control (AC);Account Management (AC-2);;aws;;MANUAL;Manual check;manual_check;manual;False;Manual check\r\n"
        assert content == expected_csv
