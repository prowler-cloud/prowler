from datetime import datetime
from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.kisa_ismsp.kisa_ismsp_azure import AzureKISAISMSP
from prowler.lib.outputs.compliance.kisa_ismsp.models import AzureKISAISMSPModel
from tests.lib.outputs.compliance.fixtures import KISA_ISMSP_AZURE
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
)


class TestAzureKISAISMSP:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                provider="azure",
                compliance={"KISA-ISMS-P-2023": ["2.5.1"]},
                account_name=AZURE_SUBSCRIPTION_NAME,
                account_uid=AZURE_SUBSCRIPTION_ID,
                region="",
            )
        ]

        output = AzureKISAISMSP(findings, KISA_ISMSP_AZURE)
        output_data = output.data[0]
        assert isinstance(output_data, AzureKISAISMSPModel)
        assert output_data.Provider == "azure"
        assert output_data.Framework == KISA_ISMSP_AZURE.Framework
        assert output_data.Name == KISA_ISMSP_AZURE.Name
        assert output_data.SubscriptionId == AZURE_SUBSCRIPTION_ID
        assert output_data.Location == ""
        assert output_data.Description == KISA_ISMSP_AZURE.Description
        assert output_data.Requirements_Id == KISA_ISMSP_AZURE.Requirements[0].Id
        assert (
            output_data.Requirements_Name
            == KISA_ISMSP_AZURE.Requirements[0].Name
        )
        assert (
            output_data.Requirements_Description
            == KISA_ISMSP_AZURE.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Domain
            == KISA_ISMSP_AZURE.Requirements[0].Attributes[0].Domain
        )
        assert (
            output_data.Requirements_Attributes_Subdomain
            == KISA_ISMSP_AZURE.Requirements[0].Attributes[0].Subdomain
        )
        assert (
            output_data.Requirements_Attributes_Section
            == KISA_ISMSP_AZURE.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_AuditChecklist
            == KISA_ISMSP_AZURE.Requirements[0].Attributes[0].AuditChecklist
        )
        assert (
            output_data.Requirements_Attributes_RelatedRegulations
            == KISA_ISMSP_AZURE.Requirements[0].Attributes[0].RelatedRegulations
        )
        assert (
            output_data.Requirements_Attributes_AuditEvidence
            == KISA_ISMSP_AZURE.Requirements[0].Attributes[0].AuditEvidence
        )
        assert (
            output_data.Requirements_Attributes_NonComplianceCases
            == KISA_ISMSP_AZURE.Requirements[0].Attributes[0].NonComplianceCases
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "service_test_check_id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "azure"
        assert output_data_manual.Framework == KISA_ISMSP_AZURE.Framework
        assert output_data_manual.Name == KISA_ISMSP_AZURE.Name
        assert output_data_manual.SubscriptionId == ""
        assert output_data_manual.Location == ""
        assert output_data_manual.Requirements_Id == KISA_ISMSP_AZURE.Requirements[1].Id
        assert (
            output_data_manual.Requirements_Description
            == KISA_ISMSP_AZURE.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Domain
            == KISA_ISMSP_AZURE.Requirements[1].Attributes[0].Domain
        )
        assert (
            output_data_manual.Requirements_Attributes_Subdomain
            == KISA_ISMSP_AZURE.Requirements[1].Attributes[0].Subdomain
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == KISA_ISMSP_AZURE.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_AuditChecklist
            == KISA_ISMSP_AZURE.Requirements[1].Attributes[0].AuditChecklist
        )
        assert (
            output_data_manual.Requirements_Attributes_RelatedRegulations
            == KISA_ISMSP_AZURE.Requirements[1].Attributes[0].RelatedRegulations
        )
        assert (
            output_data_manual.Requirements_Attributes_AuditEvidence
            == KISA_ISMSP_AZURE.Requirements[1].Attributes[0].AuditEvidence
        )
        assert (
            output_data_manual.Requirements_Attributes_NonComplianceCases
            == KISA_ISMSP_AZURE.Requirements[1].Attributes[0].NonComplianceCases
        )
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert output_data_manual.Muted is False

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.kisa_ismsp.kisa_ismsp_azure.timestamp",
        "2025-01-01 00:00:00",
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                provider="azure",
                compliance={"KISA-ISMS-P-2023": ["2.5.1"]},
                account_name=AZURE_SUBSCRIPTION_NAME,
                account_uid=AZURE_SUBSCRIPTION_ID,
                region="",
            )
        ]
        output = AzureKISAISMSP(findings, KISA_ISMSP_AZURE)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = (
            f"PROVIDER;DESCRIPTION;SUBSCRIPTIONID;LOCATION;ASSESSMENTDATE;"
            f"REQUIREMENTS_ID;REQUIREMENTS_NAME;REQUIREMENTS_DESCRIPTION;"
            f"REQUIREMENTS_ATTRIBUTES_DOMAIN;REQUIREMENTS_ATTRIBUTES_SUBDOMAIN;"
            f"REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_AUDITCHECKLIST;"
            f"REQUIREMENTS_ATTRIBUTES_RELATEDREGULATIONS;"
            f"REQUIREMENTS_ATTRIBUTES_AUDITEVIDENCE;"
            f"REQUIREMENTS_ATTRIBUTES_NONCOMPLIANCECASES;"
            f"STATUS;STATUSEXTENDED;RESOURCEID;RESOURCENAME;CHECKID;MUTED;"
            f"FRAMEWORK;NAME\r\n"
            f"azure;The ISMS-P certification, established by KISA Korea Internet & Security Agency;"
            f"{AZURE_SUBSCRIPTION_ID};;{datetime.now()};"
            f"2.5.1;User Account Management;User account management for information systems;"
            f"2. Protection Measure Requirements;"
            f"2.5. Authentication and Authorization Management;"
            f"2.5.1 User Account Management;"
            f"['Has the organization established formal procedures for registering and deleting user accounts?', 'Is access limited to the minimum necessary for each job?'];"
            f"['Personal Information Protection Act, Article 29', 'Standards for Ensuring the Safety of Personal Information, Article 5'];"
            f"['User account and access request forms', 'Access classification table for information systems'];"
            f"['Case 1: User registration processed without proper approval records.', 'Case 2: Users granted excessive permissions beyond job requirements.'];"
            f"PASS;;;;service_test_check_id;False;KISA-ISMS-P;"
            f"KISA ISMS compliance framework 2023\r\n"
            f"azure;The ISMS-P certification, established by KISA Korea Internet & Security Agency;"
            f";;{datetime.now()};"
            f"2.5.2;User Identification;User identification for information systems;"
            f"2. Protection Measure Requirements;"
            f"2.5. Authentication and Authorization Management;"
            f"2.5.2 User Identification;"
            f"['Are unique identifiers assigned to users?', 'Is the use of easily guessable identifiers restricted?'];"
            f"['Personal Information Protection Act, Article 29', 'Standards for Ensuring the Safety of Personal Information, Article 5'];"
            f"['Login screen for information systems', 'Lists of administrators and users'];"
            f"['Case 1: Default administrator accounts still in use.', 'Case 2: Developers sharing accounts without approval.'];"
            f"MANUAL;Manual check;manual_check;Manual check;manual;False;KISA-ISMS-P;"
            f"KISA ISMS compliance framework 2023\r\n"
        )
        assert content == expected_csv
