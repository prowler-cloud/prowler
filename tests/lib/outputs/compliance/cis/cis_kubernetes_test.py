from datetime import datetime
from io import StringIO

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.cis.cis_kubernetes import KubernetesCIS
from prowler.lib.outputs.compliance.cis.models import KubernetesCISModel
from tests.lib.outputs.compliance.fixtures import CIS_1_8_KUBERNETES
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.kubernetes.kubernetes_fixtures import (
    KUBERNETES_CLUSTER_NAME,
    KUBERNETES_NAMESPACE,
)


class TestKubernetesCIS:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                provider="kubernetes",
                compliance={"CIS-1.8": "1.1.3"},
                account_name=KUBERNETES_CLUSTER_NAME,
                account_uid=KUBERNETES_CLUSTER_NAME,
                region=KUBERNETES_NAMESPACE,
            )
        ]

        output = KubernetesCIS(findings, CIS_1_8_KUBERNETES)
        output_data = output.data[0]
        assert isinstance(output_data, KubernetesCISModel)
        assert output_data.Provider == "kubernetes"
        assert output_data.Context == KUBERNETES_CLUSTER_NAME
        assert output_data.Namespace == KUBERNETES_NAMESPACE
        assert output_data.Description == CIS_1_8_KUBERNETES.Description
        assert output_data.Requirements_Id == CIS_1_8_KUBERNETES.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == CIS_1_8_KUBERNETES.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Section
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_Profile
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].Profile
        )
        assert (
            output_data.Requirements_Attributes_AssessmentStatus
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].AssessmentStatus
        )
        assert (
            output_data.Requirements_Attributes_Description
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].Description
        )
        assert (
            output_data.Requirements_Attributes_RationaleStatement
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].RationaleStatement
        )
        assert (
            output_data.Requirements_Attributes_ImpactStatement
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].ImpactStatement
        )
        assert (
            output_data.Requirements_Attributes_RemediationProcedure
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].RemediationProcedure
        )
        assert (
            output_data.Requirements_Attributes_AuditProcedure
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].AuditProcedure
        )
        assert (
            output_data.Requirements_Attributes_AdditionalInformation
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].AdditionalInformation
        )
        assert (
            output_data.Requirements_Attributes_References
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].References
        )
        assert (
            output_data.Requirements_Attributes_DefaultValue
            == CIS_1_8_KUBERNETES.Requirements[0].Attributes[0].DefaultValue
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "test-check-id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "kubernetes"
        assert output_data_manual.Context == ""
        assert output_data_manual.Namespace == ""
        assert output_data_manual.Description == CIS_1_8_KUBERNETES.Description
        assert (
            output_data_manual.Requirements_Id == CIS_1_8_KUBERNETES.Requirements[1].Id
        )
        assert (
            output_data_manual.Requirements_Description
            == CIS_1_8_KUBERNETES.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_Profile
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].Profile
        )
        assert (
            output_data_manual.Requirements_Attributes_AssessmentStatus
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].AssessmentStatus
        )
        assert (
            output_data_manual.Requirements_Attributes_Description
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_RationaleStatement
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].RationaleStatement
        )
        assert (
            output_data_manual.Requirements_Attributes_ImpactStatement
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].ImpactStatement
        )
        assert (
            output_data_manual.Requirements_Attributes_RemediationProcedure
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].RemediationProcedure
        )
        assert (
            output_data_manual.Requirements_Attributes_AuditProcedure
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].AuditProcedure
        )
        assert (
            output_data_manual.Requirements_Attributes_AdditionalInformation
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].AdditionalInformation
        )
        assert (
            output_data_manual.Requirements_Attributes_References
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].References
        )
        assert (
            output_data_manual.Requirements_Attributes_DefaultValue
            == CIS_1_8_KUBERNETES.Requirements[1].Attributes[0].DefaultValue
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
                provider="kubernetes",
                compliance={"CIS-1.8": "1.1.3"},
                account_name=KUBERNETES_CLUSTER_NAME,
                account_uid=KUBERNETES_CLUSTER_NAME,
                region=KUBERNETES_NAMESPACE,
            )
        ]
        # Clear the data from CSV class
        output = KubernetesCIS(findings, CIS_1_8_KUBERNETES)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;CONTEXT;NAMESPACE;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_PROFILE;REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS;REQUIREMENTS_ATTRIBUTES_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_RATIONALESTATEMENT;REQUIREMENTS_ATTRIBUTES_IMPACTSTATEMENT;REQUIREMENTS_ATTRIBUTES_REMEDIATIONPROCEDURE;REQUIREMENTS_ATTRIBUTES_AUDITPROCEDURE;REQUIREMENTS_ATTRIBUTES_ADDITIONALINFORMATION;REQUIREMENTS_ATTRIBUTES_REFERENCES;REQUIREMENTS_ATTRIBUTES_DEFAULTVALUE;STATUS;STATUSEXTENDED;RESOURCEID;RESOURCENAME;CHECKID;MUTED\r\nkubernetes;This CIS Kubernetes Benchmark provides prescriptive guidance for establishing a secure configuration posture for Kubernetes v1.27.;test-cluster;test-namespace;{datetime.now()};1.1.3;Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive;1.1 Control Plane Node Configuration Files;Level 1 - Master Node;Automated;Ensure that the controller manager pod specification file has permissions of `600` or more restrictive.;The controller manager pod specification file controls various parameters that set the behavior of the Controller Manager on the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.;;Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` chmod 600 /etc/kubernetes/manifests/kube-controller-manager.yaml ```;Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` stat -c %a /etc/kubernetes/manifests/kube-controller-manager.yaml ```  Verify that the permissions are `600` or more restrictive.;;https://kubernetes.io/docs/admin/kube-apiserver/;By default, the `kube-controller-manager.yaml` file has permissions of `640`.;PASS;;;;test-check-id;False\r\nkubernetes;This CIS Kubernetes Benchmark provides prescriptive guidance for establishing a secure configuration posture for Kubernetes v1.27.;;;{datetime.now()};1.1.4;Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive;1.1 Control Plane Node Configuration Files;Level 1 - Master Node;Automated;Ensure that the controller manager pod specification file has permissions of `600` or more restrictive.;The controller manager pod specification file controls various parameters that set the behavior of the Controller Manager on the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.;;Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` chmod 600 /etc/kubernetes/manifests/kube-controller-manager.yaml ```;Run the below command (based on the file location on your system) on the Control Plane node. For example,  ``` stat -c %a /etc/kubernetes/manifests/kube-controller-manager.yaml ```  Verify that the permissions are `600` or more restrictive.;;https://kubernetes.io/docs/admin/kube-apiserver/;By default, the `kube-controller-manager.yaml` file has permissions of `640`.;MANUAL;Manual check;manual_check;Manual check;manual;False\r\n"
        assert content == expected_csv
