from datetime import datetime
from io import StringIO

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.cis.cis_gcp import GCPCIS
from prowler.lib.outputs.compliance.cis.models import GCPCISModel
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
        assert isinstance(output_data, GCPCISModel)
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
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "test-check-id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "gcp"
        assert output_data_manual.ProjectId == ""
        assert output_data_manual.Location == ""
        assert output_data_manual.Description == CIS_2_0_GCP.Description
        assert output_data_manual.Requirements_Id == CIS_2_0_GCP.Requirements[1].Id
        assert (
            output_data_manual.Requirements_Description
            == CIS_2_0_GCP.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == CIS_2_0_GCP.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_Profile
            == CIS_2_0_GCP.Requirements[1].Attributes[0].Profile
        )
        assert (
            output_data_manual.Requirements_Attributes_AssessmentStatus
            == CIS_2_0_GCP.Requirements[1].Attributes[0].AssessmentStatus
        )
        assert (
            output_data_manual.Requirements_Attributes_Description
            == CIS_2_0_GCP.Requirements[1].Attributes[0].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_RationaleStatement
            == CIS_2_0_GCP.Requirements[1].Attributes[0].RationaleStatement
        )
        assert (
            output_data_manual.Requirements_Attributes_ImpactStatement
            == CIS_2_0_GCP.Requirements[1].Attributes[0].ImpactStatement
        )
        assert (
            output_data_manual.Requirements_Attributes_RemediationProcedure
            == CIS_2_0_GCP.Requirements[1].Attributes[0].RemediationProcedure
        )
        assert (
            output_data_manual.Requirements_Attributes_AuditProcedure
            == CIS_2_0_GCP.Requirements[1].Attributes[0].AuditProcedure
        )
        assert (
            output_data_manual.Requirements_Attributes_AdditionalInformation
            == CIS_2_0_GCP.Requirements[1].Attributes[0].AdditionalInformation
        )
        assert (
            output_data_manual.Requirements_Attributes_References
            == CIS_2_0_GCP.Requirements[1].Attributes[0].References
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
                provider="gcp",
                compliance={"CIS-2.0": "2.13"},
                account_name=GCP_PROJECT_ID,
                account_uid=GCP_PROJECT_ID,
                region="",
            )
        ]
        # Clear the data from CSV class
        output = GCPCIS(findings, CIS_2_0_GCP)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;PROJECTID;LOCATION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_PROFILE;REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS;REQUIREMENTS_ATTRIBUTES_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_RATIONALESTATEMENT;REQUIREMENTS_ATTRIBUTES_IMPACTSTATEMENT;REQUIREMENTS_ATTRIBUTES_REMEDIATIONPROCEDURE;REQUIREMENTS_ATTRIBUTES_AUDITPROCEDURE;REQUIREMENTS_ATTRIBUTES_ADDITIONALINFORMATION;REQUIREMENTS_ATTRIBUTES_REFERENCES;STATUS;STATUSEXTENDED;RESOURCEID;RESOURCENAME;CHECKID;MUTED\r\ngcp;This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Google Cloud Computing Platform;123456789012;;{datetime.now()};2.13;Ensure That Microsoft Defender for Databases Is Set To 'On';2. Logging and Monitoring;Level 1;Automated;GCP Cloud Asset Inventory is services that provides a historical view of GCP resources and IAM policies through a time-series database. The information recorded includes metadata on Google Cloud resources, metadata on policies set on Google Cloud projects or resources, and runtime information gathered within a Google Cloud resource.;The GCP resources and IAM policies captured by GCP Cloud Asset Inventory enables security analysis, resource change tracking, and compliance auditing.  It is recommended GCP Cloud Asset Inventory be enabled for all GCP projects.;;**From Google Cloud Console**  Enable the Cloud Asset API:  1. Go to `API & Services/Library` by visiting https://console.cloud.google.com/apis/library(https://console.cloud.google.com/apis/library) 2. Search for `Cloud Asset API` and select the result for _Cloud Asset API_ 3. Click the `ENABLE` button.  **From Google Cloud CLI**  Enable the Cloud Asset API:  1. Enable the Cloud Asset API through the services interface: ``` gcloud services enable cloudasset.googleapis.com ```;**From Google Cloud Console**  Ensure that the Cloud Asset API is enabled:  1. Go to `API & Services/Library` by visiting https://console.cloud.google.com/apis/library(https://console.cloud.google.com/apis/library) 2. Search for `Cloud Asset API` and select the result for _Cloud Asset API_ 3. Ensure that `API Enabled` is displayed.  **From Google Cloud CLI**  Ensure that the Cloud Asset API is enabled:  1. Query enabled services: ``` gcloud services list --enabled --filter=name:cloudasset.googleapis.com ``` If the API is listed, then it is enabled. If the response is `Listed 0 items` the API is not enabled.;Additional info - Cloud Asset Inventory only keeps a five-week history of Google Cloud asset metadata. If a longer history is desired, automation to export the history to Cloud Storage or BigQuery should be evaluated.;https://cloud.google.com/asset-inventory/docs;PASS;;;;test-check-id;False\r\ngcp;This CIS Benchmark is the product of a community consensus process and consists of secure configuration guidelines developed for Google Cloud Computing Platform;;;{datetime.now()};2.14;Ensure That Microsoft Defender for Databases Is Set To 'On';2. Logging and Monitoring;Level 1;Automated;GCP Cloud Asset Inventory is services that provides a historical view of GCP resources and IAM policies through a time-series database. The information recorded includes metadata on Google Cloud resources, metadata on policies set on Google Cloud projects or resources, and runtime information gathered within a Google Cloud resource.;The GCP resources and IAM policies captured by GCP Cloud Asset Inventory enables security analysis, resource change tracking, and compliance auditing.  It is recommended GCP Cloud Asset Inventory be enabled for all GCP projects.;;**From Google Cloud Console**  Enable the Cloud Asset API:  1. Go to `API & Services/Library` by visiting https://console.cloud.google.com/apis/library(https://console.cloud.google.com/apis/library) 2. Search for `Cloud Asset API` and select the result for _Cloud Asset API_ 3. Click the `ENABLE` button.  **From Google Cloud CLI**  Enable the Cloud Asset API:  1. Enable the Cloud Asset API through the services interface: ``` gcloud services enable cloudasset.googleapis.com ```;**From Google Cloud Console**  Ensure that the Cloud Asset API is enabled:  1. Go to `API & Services/Library` by visiting https://console.cloud.google.com/apis/library(https://console.cloud.google.com/apis/library) 2. Search for `Cloud Asset API` and select the result for _Cloud Asset API_ 3. Ensure that `API Enabled` is displayed.  **From Google Cloud CLI**  Ensure that the Cloud Asset API is enabled:  1. Query enabled services: ``` gcloud services list --enabled --filter=name:cloudasset.googleapis.com ``` If the API is listed, then it is enabled. If the response is `Listed 0 items` the API is not enabled.;Additional info - Cloud Asset Inventory only keeps a five-week history of Google Cloud asset metadata. If a longer history is desired, automation to export the history to Cloud Storage or BigQuery should be evaluated.;https://cloud.google.com/asset-inventory/docs;MANUAL;Manual check;manual_check;Manual check;manual;False"
        assert expected_csv in content
