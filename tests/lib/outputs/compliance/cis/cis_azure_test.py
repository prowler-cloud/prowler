from datetime import datetime
from io import StringIO

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.cis.cis_azure import AzureCIS
from prowler.lib.outputs.compliance.cis.models import AzureCISModel
from tests.lib.outputs.compliance.fixtures import CIS_2_0_AZURE
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
)


class TestAzureCIS:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                provider="azure",
                compliance={"CIS-2.0": "2.1.3"},
                account_name=AZURE_SUBSCRIPTION_NAME,
                account_uid=AZURE_SUBSCRIPTION_ID,
                region="",
            )
        ]

        output = AzureCIS(findings, CIS_2_0_AZURE)
        output_data = output.data[0]
        assert isinstance(output_data, AzureCISModel)
        assert output_data.Provider == "azure"
        assert output_data.SubscriptionId == AZURE_SUBSCRIPTION_ID
        assert output_data.Location == ""
        assert output_data.Description == CIS_2_0_AZURE.Description
        assert output_data.Requirements_Id == CIS_2_0_AZURE.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == CIS_2_0_AZURE.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Section
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_Profile
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].Profile
        )
        assert (
            output_data.Requirements_Attributes_AssessmentStatus
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].AssessmentStatus
        )
        assert (
            output_data.Requirements_Attributes_Description
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].Description
        )
        assert (
            output_data.Requirements_Attributes_RationaleStatement
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].RationaleStatement
        )
        assert (
            output_data.Requirements_Attributes_ImpactStatement
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].ImpactStatement
        )
        assert (
            output_data.Requirements_Attributes_RemediationProcedure
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].RemediationProcedure
        )
        assert (
            output_data.Requirements_Attributes_AuditProcedure
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].AuditProcedure
        )
        assert (
            output_data.Requirements_Attributes_AdditionalInformation
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].AdditionalInformation
        )
        assert (
            output_data.Requirements_Attributes_References
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].References
        )
        assert (
            output_data.Requirements_Attributes_DefaultValue
            == CIS_2_0_AZURE.Requirements[0].Attributes[0].DefaultValue
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "test-check-id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "azure"
        assert output_data_manual.SubscriptionId == ""
        assert output_data_manual.Location == ""
        assert output_data_manual.Description == CIS_2_0_AZURE.Description
        assert output_data_manual.Requirements_Id == CIS_2_0_AZURE.Requirements[1].Id
        assert (
            output_data_manual.Requirements_Description
            == CIS_2_0_AZURE.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_Profile
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].Profile
        )
        assert (
            output_data_manual.Requirements_Attributes_AssessmentStatus
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].AssessmentStatus
        )
        assert (
            output_data_manual.Requirements_Attributes_Description
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_RationaleStatement
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].RationaleStatement
        )
        assert (
            output_data_manual.Requirements_Attributes_ImpactStatement
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].ImpactStatement
        )
        assert (
            output_data_manual.Requirements_Attributes_RemediationProcedure
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].RemediationProcedure
        )
        assert (
            output_data_manual.Requirements_Attributes_AuditProcedure
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].AuditProcedure
        )
        assert (
            output_data_manual.Requirements_Attributes_AdditionalInformation
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].AdditionalInformation
        )
        assert (
            output_data_manual.Requirements_Attributes_References
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].References
        )
        assert (
            output_data_manual.Requirements_Attributes_DefaultValue
            == CIS_2_0_AZURE.Requirements[1].Attributes[0].DefaultValue
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
            generate_finding_output(
                provider="azure",
                compliance={"CIS-2.0": "2.1.3"},
                account_name=AZURE_SUBSCRIPTION_NAME,
                account_uid=AZURE_SUBSCRIPTION_ID,
                region="",
            )
        ]
        # Clear the data from CSV class
        output = AzureCIS(findings, CIS_2_0_AZURE)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;SUBSCRIPTIONID;LOCATION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_PROFILE;REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS;REQUIREMENTS_ATTRIBUTES_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_RATIONALESTATEMENT;REQUIREMENTS_ATTRIBUTES_IMPACTSTATEMENT;REQUIREMENTS_ATTRIBUTES_REMEDIATIONPROCEDURE;REQUIREMENTS_ATTRIBUTES_AUDITPROCEDURE;REQUIREMENTS_ATTRIBUTES_ADDITIONALINFORMATION;REQUIREMENTS_ATTRIBUTES_DEFAULTVALUE;REQUIREMENTS_ATTRIBUTES_REFERENCES;STATUS;STATUSEXTENDED;RESOURCEID;RESOURCENAME;CHECKID;MUTED\r\nazure;The CIS Azure Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Azure with an emphasis on foundational, testable, and architecture agnostic settings.;{AZURE_SUBSCRIPTION_ID};;{datetime.now()};2.1.3;Ensure That Microsoft Defender for Databases Is Set To 'On';2.1 Microsoft Defender for Cloud;Level 2;Manual;Turning on Microsoft Defender for Databases enables threat detection for the instances running your database software. This provides threat intelligence, anomaly detection, and behavior analytics in the Azure Microsoft Defender for Cloud. Instead of being enabled on services like Platform as a Service (PaaS), this implementation will run within your instances as Infrastructure as a Service (IaaS) on the Operating Systems hosting your databases.;Enabling Microsoft Defender for Azure SQL Databases allows your organization more granular control of the infrastructure running your database software. Instead of waiting on Microsoft release updates or other similar processes, you can manage them yourself. Threat detection is provided by the Microsoft Security Response Center (MSRC).;Running Defender on Infrastructure as a service (IaaS) may incur increased costs associated with running the service and the instance it is on. Similarly, you will need qualified personnel to maintain the operating system and software updates. If it is not maintained, security patches will not be applied and it may be open to vulnerabilities.;From Azure Portal 1. Go to Microsoft Defender for Cloud 2. Select Environment Settings 3. Click on the subscription name 4. Select Defender plans 5. Set Databases Status to On 6. Select Save Review the chosen pricing tier. For the Azure Databases resource review the different plan information and choose one that fits the needs of your organization. From Azure CLI Run the following commands: az security pricing create -n 'SqlServers' --tier 'Standard' az security pricing create -n 'SqlServerVirtualMachines' --tier 'Standard' az security pricing create -n 'OpenSourceRelationalDatabases' --tier 'Standard' az security pricing create -n 'CosmosDbs' --tier 'Standard' From Azure PowerShell Run the following commands: Set-AzSecurityPricing -Name 'SqlServers' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'SqlServerVirtualMachines' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'OpenSourceRelationalDatabases' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'CosmosDbs' -PricingTier 'Standard';From Azure Portal 1. Go to Microsoft Defender for Cloud 2. Select Environment Settings 3. Click on the subscription name 4. Select Defender plans 5. Ensure Databases Status is set to On 6. Review the chosen pricing tier From Azure CLI Ensure the output of the below commands is Standard az security pricing show -n 'SqlServers' az security pricing show -n 'SqlServerVirtualMachines' az security pricing show -n 'OpenSourceRelationalDatabases' az security pricing show -n 'CosmosDbs' If the output of any of the above commands shows pricingTier with a value of Free, the setting is out of compliance. From PowerShell Connect-AzAccount Get-AzSecurityPricing |select-object Name,PricingTier |where-object {{$_.Name -match 'Sql' -or $_.Name -match 'Cosmos' -or $_.Name -match 'OpenSource'}} Ensure the output shows Standard for each database type under the PricingTier column. Any that show Free are considered out of compliance.;;By default, Microsoft Defender plan is off.;https://docs.microsoft.com/en-us/azure/azure-sql/database/azure-defender-for-sql?view=azuresql:https://docs.microsoft.com/en-us/azure/defender-for-cloud/quickstart-enable-database-protections:https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-usage:https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities:https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list:https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-logging-threat-detection#lt-1-enable-threat-detection-capabilities;PASS;;;;test-check-id;False\r\nazure;The CIS Azure Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Azure with an emphasis on foundational, testable, and architecture agnostic settings.;;;{datetime.now()};2.1.4;Ensure That Microsoft Defender for Databases Is Set To 'On';2.1 Microsoft Defender for Cloud;Level 2;Manual;Turning on Microsoft Defender for Databases enables threat detection for the instances running your database software. This provides threat intelligence, anomaly detection, and behavior analytics in the Azure Microsoft Defender for Cloud. Instead of being enabled on services like Platform as a Service (PaaS), this implementation will run within your instances as Infrastructure as a Service (IaaS) on the Operating Systems hosting your databases.;Enabling Microsoft Defender for Azure SQL Databases allows your organization more granular control of the infrastructure running your database software. Instead of waiting on Microsoft release updates or other similar processes, you can manage them yourself. Threat detection is provided by the Microsoft Security Response Center (MSRC).;Running Defender on Infrastructure as a service (IaaS) may incur increased costs associated with running the service and the instance it is on. Similarly, you will need qualified personnel to maintain the operating system and software updates. If it is not maintained, security patches will not be applied and it may be open to vulnerabilities.;From Azure Portal 1. Go to Microsoft Defender for Cloud 2. Select Environment Settings 3. Click on the subscription name 4. Select Defender plans 5. Set Databases Status to On 6. Select Save Review the chosen pricing tier. For the Azure Databases resource review the different plan information and choose one that fits the needs of your organization. From Azure CLI Run the following commands: az security pricing create -n 'SqlServers' --tier 'Standard' az security pricing create -n 'SqlServerVirtualMachines' --tier 'Standard' az security pricing create -n 'OpenSourceRelationalDatabases' --tier 'Standard' az security pricing create -n 'CosmosDbs' --tier 'Standard' From Azure PowerShell Run the following commands: Set-AzSecurityPricing -Name 'SqlServers' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'SqlServerVirtualMachines' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'OpenSourceRelationalDatabases' -PricingTier 'Standard' Set-AzSecurityPricing -Name 'CosmosDbs' -PricingTier 'Standard';From Azure Portal 1. Go to Microsoft Defender for Cloud 2. Select Environment Settings 3. Click on the subscription name 4. Select Defender plans 5. Ensure Databases Status is set to On 6. Review the chosen pricing tier From Azure CLI Ensure the output of the below commands is Standard az security pricing show -n 'SqlServers' az security pricing show -n 'SqlServerVirtualMachines' az security pricing show -n 'OpenSourceRelationalDatabases' az security pricing show -n 'CosmosDbs' If the output of any of the above commands shows pricingTier with a value of Free, the setting is out of compliance. From PowerShell Connect-AzAccount Get-AzSecurityPricing |select-object Name,PricingTier |where-object {{$_.Name -match 'Sql' -or $_.Name -match 'Cosmos' -or $_.Name -match 'OpenSource'}} Ensure the output shows Standard for each database type under the PricingTier column. Any that show Free are considered out of compliance.;;By default, Microsoft Defender plan is off.;https://docs.microsoft.com/en-us/azure/azure-sql/database/azure-defender-for-sql?view=azuresql:https://docs.microsoft.com/en-us/azure/defender-for-cloud/quickstart-enable-database-protections:https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-usage:https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities:https://docs.microsoft.com/en-us/rest/api/securitycenter/pricings/list:https://docs.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-logging-threat-detection#lt-1-enable-threat-detection-capabilities;MANUAL;Manual check;manual_check;Manual check;manual;False\r\n"
        assert content == expected_csv
