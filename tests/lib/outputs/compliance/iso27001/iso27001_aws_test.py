from datetime import datetime
from io import StringIO

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.iso27001.iso27001_aws import AWSISO27001
from prowler.lib.outputs.compliance.iso27001.models import AWSISO27001Model
from tests.lib.outputs.compliance.fixtures import ISO27001_2013_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestAWSISO27001:
    def test_output_transform(self):
        findings = [generate_finding_output(compliance={"ISO27001-2013": "A.10.1"})]

        output = AWSISO27001(findings, ISO27001_2013_AWS)
        output_data = output.data[0]
        assert isinstance(output_data, AWSISO27001Model)
        assert output_data.Provider == "aws"
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Description == ISO27001_2013_AWS.Description
        assert (
            output_data.Requirements_Attributes_Category
            == ISO27001_2013_AWS.Requirements[0].Attributes[0].Category
        )
        assert (
            output_data.Requirements_Attributes_Objetive_ID
            == ISO27001_2013_AWS.Requirements[0].Attributes[0].Objetive_ID
        )
        assert (
            output_data.Requirements_Attributes_Objetive_Name
            == ISO27001_2013_AWS.Requirements[0].Attributes[0].Objetive_Name
        )
        assert (
            output_data.Requirements_Attributes_Check_Summary
            == ISO27001_2013_AWS.Requirements[0].Attributes[0].Check_Summary
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
        assert output_data_manual.Description == ISO27001_2013_AWS.Description
        assert (
            output_data_manual.Requirements_Attributes_Category
            == ISO27001_2013_AWS.Requirements[1].Attributes[0].Category
        )
        assert (
            output_data_manual.Requirements_Attributes_Objetive_ID
            == ISO27001_2013_AWS.Requirements[1].Attributes[0].Objetive_ID
        )
        assert (
            output_data_manual.Requirements_Attributes_Objetive_Name
            == ISO27001_2013_AWS.Requirements[1].Attributes[0].Objetive_Name
        )
        assert (
            output_data_manual.Requirements_Attributes_Check_Summary
            == ISO27001_2013_AWS.Requirements[1].Attributes[0].Check_Summary
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
        findings = [generate_finding_output(compliance={"ISO27001-2013": "A.10.1"})]
        output = AWSISO27001(findings, ISO27001_2013_AWS)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;ACCOUNTID;REGION;ASSESSMENTDATE;REQUIREMENTS_ATTRIBUTES_CATEGORY;REQUIREMENTS_ATTRIBUTES_OBJETIVE_ID;REQUIREMENTS_ATTRIBUTES_OBJETIVE_NAME;REQUIREMENTS_ATTRIBUTES_CHECK_SUMMARY;STATUS;STATUSEXTENDED;RESOURCEID;CHECKID;MUTED;RESOURCENAME\r\naws;ISO (the International Organization for Standardization) and IEC (the International Electrotechnical Commission) form the specialized system for worldwide standardization. National bodies that are members of ISO or IEC participate in the development of International Standards through technical committees established by the respective organization to deal with particular fields of technical activity. ISO and IEC technical committees collaborate in fields of mutual interest. Other international organizations, governmental and non-governmental, in liaison with ISO and IEC, also take part in the work.;123456789012;eu-west-1;{datetime.now()};A.10 Cryptography;A.10.1;Cryptographic Controls;Setup Encryption at rest for RDS instances;PASS;;;test-check-id;False;\r\naws;ISO (the International Organization for Standardization) and IEC (the International Electrotechnical Commission) form the specialized system for worldwide standardization. National bodies that are members of ISO or IEC participate in the development of International Standards through technical committees established by the respective organization to deal with particular fields of technical activity. ISO and IEC technical committees collaborate in fields of mutual interest. Other international organizations, governmental and non-governmental, in liaison with ISO and IEC, also take part in the work.;;;{datetime.now()};A.10 Cryptography;A.10.1;Cryptographic Controls;Setup Encryption at rest for RDS instances;MANUAL;Manual check;manual_check;manual;False;Manual check\r\n"
        assert content == expected_csv
