from datetime import datetime
from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.cis.cis_m365 import M365CIS
from prowler.lib.outputs.compliance.cis.models import M365CISModel
from tests.lib.outputs.compliance.fixtures import CIS_4_0_M365
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.m365.m365_fixtures import DOMAIN, LOCATION, TENANT_ID


class TestM365CIS:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                provider="m365",
                compliance={"CIS-4.0": "2.1.3"},
                account_name=DOMAIN,
                account_uid=TENANT_ID,
                region=LOCATION,
            )
        ]
        # Clear the data from CSV class
        output = M365CIS(findings, CIS_4_0_M365)
        output_data = output.data[0]
        assert isinstance(output_data, M365CISModel)
        assert output_data.Provider == "m365"
        assert output_data.TenantId == TENANT_ID
        assert output_data.Location == LOCATION
        assert output_data.Description == CIS_4_0_M365.Description
        assert output_data.Requirements_Id == CIS_4_0_M365.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == CIS_4_0_M365.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Section
            == CIS_4_0_M365.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_SubSection
            == CIS_4_0_M365.Requirements[0].Attributes[0].SubSection
        )
        assert (
            output_data.Requirements_Attributes_Profile
            == CIS_4_0_M365.Requirements[0].Attributes[0].Profile
        )
        assert (
            output_data.Requirements_Attributes_AssessmentStatus
            == CIS_4_0_M365.Requirements[0].Attributes[0].AssessmentStatus
        )
        assert (
            output_data.Requirements_Attributes_Description
            == CIS_4_0_M365.Requirements[0].Attributes[0].Description
        )
        assert (
            output_data.Requirements_Attributes_RationaleStatement
            == CIS_4_0_M365.Requirements[0].Attributes[0].RationaleStatement
        )
        assert (
            output_data.Requirements_Attributes_ImpactStatement
            == CIS_4_0_M365.Requirements[0].Attributes[0].ImpactStatement
        )
        assert (
            output_data.Requirements_Attributes_RemediationProcedure
            == CIS_4_0_M365.Requirements[0].Attributes[0].RemediationProcedure
        )
        assert (
            output_data.Requirements_Attributes_AuditProcedure
            == CIS_4_0_M365.Requirements[0].Attributes[0].AuditProcedure
        )
        assert (
            output_data.Requirements_Attributes_AdditionalInformation
            == CIS_4_0_M365.Requirements[0].Attributes[0].AdditionalInformation
        )
        assert (
            output_data.Requirements_Attributes_References
            == CIS_4_0_M365.Requirements[0].Attributes[0].References
        )
        assert (
            output_data.Requirements_Attributes_DefaultValue
            == CIS_4_0_M365.Requirements[0].Attributes[0].DefaultValue
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "test-check-id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "m365"
        assert output_data_manual.TenantId == TENANT_ID
        assert output_data_manual.Location == LOCATION
        assert output_data_manual.Description == CIS_4_0_M365.Description
        assert output_data_manual.Requirements_Id == CIS_4_0_M365.Requirements[1].Id
        assert (
            output_data_manual.Requirements_Description
            == CIS_4_0_M365.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == CIS_4_0_M365.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_SubSection
            == CIS_4_0_M365.Requirements[0].Attributes[0].SubSection
        )
        assert (
            output_data_manual.Requirements_Attributes_Profile
            == CIS_4_0_M365.Requirements[1].Attributes[0].Profile
        )
        assert (
            output_data_manual.Requirements_Attributes_AssessmentStatus
            == CIS_4_0_M365.Requirements[1].Attributes[0].AssessmentStatus
        )
        assert (
            output_data_manual.Requirements_Attributes_Description
            == CIS_4_0_M365.Requirements[1].Attributes[0].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_RationaleStatement
            == CIS_4_0_M365.Requirements[1].Attributes[0].RationaleStatement
        )
        assert (
            output_data_manual.Requirements_Attributes_ImpactStatement
            == CIS_4_0_M365.Requirements[1].Attributes[0].ImpactStatement
        )
        assert (
            output_data_manual.Requirements_Attributes_RemediationProcedure
            == CIS_4_0_M365.Requirements[1].Attributes[0].RemediationProcedure
        )
        assert (
            output_data_manual.Requirements_Attributes_AuditProcedure
            == CIS_4_0_M365.Requirements[1].Attributes[0].AuditProcedure
        )
        assert (
            output_data_manual.Requirements_Attributes_AdditionalInformation
            == CIS_4_0_M365.Requirements[1].Attributes[0].AdditionalInformation
        )
        assert (
            output_data_manual.Requirements_Attributes_References
            == CIS_4_0_M365.Requirements[1].Attributes[0].References
        )
        assert (
            output_data_manual.Requirements_Attributes_DefaultValue
            == CIS_4_0_M365.Requirements[1].Attributes[0].DefaultValue
        )
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert output_data_manual.Muted is False

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.cis.cis_m365.timestamp", "2025-01-01 00:00:00"
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                provider="m365",
                compliance={"CIS-4.0": "2.1.3"},
                account_name=DOMAIN,
                account_uid=TENANT_ID,
                region=LOCATION,
            )
        ]
        # Clear the data from CSV class
        output = M365CIS(findings, CIS_4_0_M365)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()

        expected_csv = f"PROVIDER;DESCRIPTION;TENANTID;LOCATION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_SUBSECTION;REQUIREMENTS_ATTRIBUTES_PROFILE;REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS;REQUIREMENTS_ATTRIBUTES_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_RATIONALESTATEMENT;REQUIREMENTS_ATTRIBUTES_IMPACTSTATEMENT;REQUIREMENTS_ATTRIBUTES_REMEDIATIONPROCEDURE;REQUIREMENTS_ATTRIBUTES_AUDITPROCEDURE;REQUIREMENTS_ATTRIBUTES_ADDITIONALINFORMATION;REQUIREMENTS_ATTRIBUTES_DEFAULTVALUE;REQUIREMENTS_ATTRIBUTES_REFERENCES;STATUS;STATUSEXTENDED;RESOURCEID;RESOURCENAME;CHECKID;MUTED\r\nm365;The CIS Microsoft 365 Foundations Benchmark provides prescriptive guidance for configuring security options for Microsoft 365 with an emphasis on foundational, testable, and architecture agnostic settings.;00000000-0000-0000-0000-000000000000;global;{datetime.now()};2.1.3;Ensure MFA Delete is enabled on S3 buckets;2.1. Simple Storage Service (S3);;Level 1;Automated;Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.;Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.;;Perform the steps below to enable MFA delete on an S3 bucket.Note:-You cannot enable MFA Delete using the AWS Management Console. You must use the AWS CLI or API.-You must use your 'root' account to enable MFA Delete on S3 buckets.**From Command line:**1. Run the s3api put-bucket-versioning command aws s3api put-bucket-versioning --profile my-root-profile --bucket Bucket_Name --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa arn:aws:iam::aws_account_id:mfa/root-account-mfa-device passcode;Perform the steps below to confirm MFA delete is configured on an S3 Bucket**From Console:**1. Login to the S3 console at `https://console.aws.amazon.com/s3/`2. Click the `Check` box next to the Bucket name you want to confirm3. In the window under `Properties`4. Confirm that Versioning is `Enabled`5. Confirm that MFA Delete is `Enabled`**From Command Line:**1. Run the `get-bucket-versioning aws s3api get-bucket-versioning --bucket my-bucket Output example: <VersioningConfiguration xmlns=`http://s3.amazonaws.com/doc/2006-03-01/`>  <Status>Enabled</Status> <MfaDelete>Enabled</MfaDelete></VersioningConfiguration>\ If the Console or the CLI output does not show Versioning and MFA Delete `enabled` refer to the remediation below.;;By default, MFA Delete is not enabled on S3 buckets.;https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete:https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html:https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/:https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html;PASS;;;;test-check-id;False\r\nm365;The CIS Microsoft 365 Foundations Benchmark provides prescriptive guidance for configuring security options for Microsoft 365 with an emphasis on foundational, testable, and architecture agnostic settings.;00000000-0000-0000-0000-000000000000;global;{datetime.now()};2.1.4;Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive;1.1 Control Plane Node Configuration Files;;Level 1;Automated;Ensure that the controller manager pod specification file has permissions of `600` or more restrictive.;The controller manager pod specification file controls various parameters that set the behavior of the Controller Manager on the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.;;Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` chmod 600 /etc/kubernetes/manifests/kube-controller-manager.yaml ```;Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` stat -c %a /etc/kubernetes/manifests/kube-controller-manager.yaml ```  Verify that the permissions are `600` or more restrictive.;;By default, the `kube-controller-manager.yaml` file has permissions of `640`.;https://kubernetes.io/docs/admin/kube-apiserver/;MANUAL;Manual check;manual_check;Manual check;manual;False\r\n"

        assert content == expected_csv
