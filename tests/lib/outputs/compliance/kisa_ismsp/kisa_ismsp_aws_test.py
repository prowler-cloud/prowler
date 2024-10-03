from datetime import datetime
from io import StringIO

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.kisa_ismsp.kisa_ismsp_aws import AWSKISAISMSP
from prowler.lib.outputs.compliance.kisa_ismsp.models import AWSKISAISMSPModel
from tests.lib.outputs.compliance.fixtures import KISA_ISMSP_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestAWSKISAISMSP:
    def test_output_transform(self):
        findings = [generate_finding_output(compliance={"KISA-ISMS-P-2023": ["2.5.3"]})]

        output = AWSKISAISMSP(findings, KISA_ISMSP_AWS)
        output_data = output.data[0]
        assert isinstance(output_data, AWSKISAISMSPModel)
        assert output_data.Provider == "aws"
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Description == KISA_ISMSP_AWS.Description
        assert output_data.Requirements_Id == KISA_ISMSP_AWS.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == KISA_ISMSP_AWS.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Domain
            == KISA_ISMSP_AWS.Requirements[0].Attributes[0].Domain
        )
        assert (
            output_data.Requirements_Attributes_Subdomain
            == KISA_ISMSP_AWS.Requirements[0].Attributes[0].Subdomain
        )
        assert (
            output_data.Requirements_Attributes_Section
            == KISA_ISMSP_AWS.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_AuditChecklist
            == KISA_ISMSP_AWS.Requirements[0].Attributes[0].AuditChecklist
        )
        assert (
            output_data.Requirements_Attributes_RelatedRegulations
            == KISA_ISMSP_AWS.Requirements[0].Attributes[0].RelatedRegulations
        )
        assert (
            output_data.Requirements_Attributes_AuditEvidence
            == KISA_ISMSP_AWS.Requirements[0].Attributes[0].AuditEvidence
        )
        assert (
            output_data.Requirements_Attributes_NonComplianceCases
            == KISA_ISMSP_AWS.Requirements[0].Attributes[0].NonComplianceCases
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
        assert output_data_manual.Requirements_Id == KISA_ISMSP_AWS.Requirements[1].Id
        assert (
            output_data_manual.Requirements_Description
            == KISA_ISMSP_AWS.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Domain
            == KISA_ISMSP_AWS.Requirements[1].Attributes[0].Domain
        )
        assert (
            output_data_manual.Requirements_Attributes_Subdomain
            == KISA_ISMSP_AWS.Requirements[1].Attributes[0].Subdomain
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == KISA_ISMSP_AWS.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_AuditChecklist
            == KISA_ISMSP_AWS.Requirements[1].Attributes[0].AuditChecklist
        )
        assert (
            output_data_manual.Requirements_Attributes_RelatedRegulations
            == KISA_ISMSP_AWS.Requirements[1].Attributes[0].RelatedRegulations
        )
        assert (
            output_data_manual.Requirements_Attributes_AuditEvidence
            == KISA_ISMSP_AWS.Requirements[1].Attributes[0].AuditEvidence
        )
        assert (
            output_data_manual.Requirements_Attributes_NonComplianceCases
            == KISA_ISMSP_AWS.Requirements[1].Attributes[0].NonComplianceCases
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
        findings = [generate_finding_output(compliance={"KISA-ISMS-P-2023": ["2.5.3"]})]
        output = AWSKISAISMSP(findings, KISA_ISMSP_AWS)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;ACCOUNTID;REGION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_NAME;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_DOMAIN;REQUIREMENTS_ATTRIBUTES_SUBDOMAIN;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_AUDITCHECKLIST;REQUIREMENTS_ATTRIBUTES_RELATEDREGULATIONS;REQUIREMENTS_ATTRIBUTES_AUDITEVIDENCE;REQUIREMENTS_ATTRIBUTES_NONCOMPLIANCECASES;STATUS;STATUSEXTENDED;RESOURCEID;RESOURCENAME;CHECKID;MUTED\r\naws;The ISMS-P certification, established by KISA Korea Internet & Security Agency;123456789012;eu-west-1;{datetime.now()};2.5.3;User Authentication;User access to information systems;2. Protection Measure Requirements;2.5. Authentication and Authorization Management;2.5.3 User Authentication;['Is access to information systems and personal information controlled through secure authentication?', 'Are login attempt limitations enforced?'];['Personal Information Protection Act, Article 29', 'Standards for Ensuring the Safety of Personal Information, Article 5'];['Login screen for information systems', 'Login failure message screen'];['Case 1: Insufficient authentication when accessing information systems externally.', 'Case 2: No limitation on login failure attempts.'];PASS;;;;test-check-id;False\r\naws;The ISMS-P certification, established by KISA Korea Internet & Security Agency;;;{datetime.now()};2.5.4;User Authentication;User access to information systems;2. Protection Measure Requirements;2.5. Authentication and Authorization Management;2.5.3 User Authentication;['Is access to information systems and personal information controlled through secure authentication?', 'Are login attempt limitations enforced?'];['Personal Information Protection Act, Article 29', 'Standards for Ensuring the Safety of Personal Information, Article 5'];['Login screen for information systems', 'Login failure message screen'];['Case 1: Insufficient authentication when accessing information systems externally.', 'Case 2: No limitation on login failure attempts.'];MANUAL;Manual check;manual_check;Manual check;manual;False\r\n"
        assert content == expected_csv
