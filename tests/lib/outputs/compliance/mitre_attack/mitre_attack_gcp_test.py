from datetime import datetime
from io import StringIO

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_gcp import GCPMitreAttack
from prowler.lib.outputs.compliance.mitre_attack.models import GCPMitreAttackModel
from prowler.lib.outputs.utils import unroll_list
from tests.lib.outputs.compliance.fixtures import MITRE_ATTACK_GCP
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID


class TestGCPMITREAttack:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                provider="gcp",
                compliance={"MITRE-ATTACK": "T1190"},
                account_name=GCP_PROJECT_ID,
                account_uid=GCP_PROJECT_ID,
                region="",
            )
        ]

        output = GCPMitreAttack(findings, MITRE_ATTACK_GCP)
        output_data = output.data[0]
        assert isinstance(output_data, GCPMitreAttackModel)
        assert output_data.Provider == "gcp"
        assert output_data.Description == MITRE_ATTACK_GCP.Description
        assert output_data.ProjectId == GCP_PROJECT_ID
        assert output_data.Location == ""
        assert output_data.Requirements_Id == MITRE_ATTACK_GCP.Requirements[0].Id
        assert output_data.Requirements_Name == MITRE_ATTACK_GCP.Requirements[0].Name
        assert (
            output_data.Requirements_Description
            == MITRE_ATTACK_GCP.Requirements[0].Description
        )
        assert output_data.Requirements_Tactics == unroll_list(
            MITRE_ATTACK_GCP.Requirements[0].Tactics
        )
        assert output_data.Requirements_SubTechniques == unroll_list(
            MITRE_ATTACK_GCP.Requirements[0].SubTechniques
        )
        assert output_data.Requirements_Platforms == unroll_list(
            MITRE_ATTACK_GCP.Requirements[0].Platforms
        )
        assert (
            output_data.Requirements_TechniqueURL
            == MITRE_ATTACK_GCP.Requirements[0].TechniqueURL
        )
        assert output_data.Requirements_Attributes_Services == ", ".join(
            attribute.GCPService
            for attribute in MITRE_ATTACK_GCP.Requirements[0].Attributes
        )
        assert output_data.Requirements_Attributes_Categories == ", ".join(
            attribute.Category
            for attribute in MITRE_ATTACK_GCP.Requirements[0].Attributes
        )
        assert output_data.Requirements_Attributes_Values == ", ".join(
            attribute.Value for attribute in MITRE_ATTACK_GCP.Requirements[0].Attributes
        )
        assert output_data.Requirements_Attributes_Comments == ", ".join(
            attribute.Comment
            for attribute in MITRE_ATTACK_GCP.Requirements[0].Attributes
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "test-check-id"
        assert not output_data.Muted
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "gcp"
        assert output_data_manual.ProjectId == ""
        assert output_data_manual.Location == ""
        assert output_data_manual.Requirements_Id == MITRE_ATTACK_GCP.Requirements[1].Id
        assert (
            output_data_manual.Requirements_Name
            == MITRE_ATTACK_GCP.Requirements[1].Name
        )
        assert (
            output_data_manual.Requirements_Description
            == MITRE_ATTACK_GCP.Requirements[1].Description
        )
        assert output_data_manual.Requirements_Tactics == unroll_list(
            MITRE_ATTACK_GCP.Requirements[1].Tactics
        )
        assert output_data_manual.Requirements_SubTechniques == unroll_list(
            MITRE_ATTACK_GCP.Requirements[1].SubTechniques
        )
        assert output_data_manual.Requirements_Platforms == unroll_list(
            MITRE_ATTACK_GCP.Requirements[1].Platforms
        )
        assert (
            output_data_manual.Requirements_TechniqueURL
            == MITRE_ATTACK_GCP.Requirements[1].TechniqueURL
        )
        assert output_data_manual.Requirements_Attributes_Services == ", ".join(
            attribute.GCPService
            for attribute in MITRE_ATTACK_GCP.Requirements[1].Attributes
        )
        assert output_data_manual.Requirements_Attributes_Categories == ", ".join(
            attribute.Category
            for attribute in MITRE_ATTACK_GCP.Requirements[1].Attributes
        )
        assert output_data_manual.Requirements_Attributes_Values == ", ".join(
            attribute.Value for attribute in MITRE_ATTACK_GCP.Requirements[1].Attributes
        )
        assert output_data_manual.Requirements_Attributes_Comments == ", ".join(
            attribute.Comment
            for attribute in MITRE_ATTACK_GCP.Requirements[1].Attributes
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
                compliance={"MITRE-ATTACK": "T1190"},
                account_name=GCP_PROJECT_ID,
                account_uid=GCP_PROJECT_ID,
                region="",
            )
        ]
        output = GCPMitreAttack(findings, MITRE_ATTACK_GCP)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;PROJECTID;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_NAME;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_TACTICS;REQUIREMENTS_SUBTECHNIQUES;REQUIREMENTS_PLATFORMS;REQUIREMENTS_TECHNIQUEURL;REQUIREMENTS_ATTRIBUTES_SERVICES;REQUIREMENTS_ATTRIBUTES_CATEGORIES;REQUIREMENTS_ATTRIBUTES_VALUES;REQUIREMENTS_ATTRIBUTES_COMMENTS;STATUS;STATUSEXTENDED;RESOURCEID;CHECKID;MUTED;RESOURCENAME;LOCATION\r\ngcp;MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.;123456789012;{datetime.now()};T1190;Exploit Public-Facing Application;Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.;Initial Access;;Containers | IaaS | Linux | Network | Windows | macOS;https://attack.mitre.org/techniques/T1190/;Artifact Registry;Protect;Partial;Once this control is deployed, it can detect known vulnerabilities in various Linux OS packages. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and is not effective against zero day attacks, vulnerabilities with no available patch, and other end-of-life packages.;PASS;;;test-check-id;False;;\r\ngcp;MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.;;{datetime.now()};T1191;Exploit Public-Facing Application;Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.;Initial Access;;Containers | IaaS | Linux | Network | Windows | macOS;https://attack.mitre.org/techniques/T1190/;Artifact Registry;Protect;Partial;Once this control is deployed, it can detect known vulnerabilities in various Linux OS packages. This information can be used to patch, isolate, or remove vulnerable software and machines. This control does not directly protect against exploitation and is not effective against zero day attacks, vulnerabilities with no available patch, and other end-of-life packages.;MANUAL;Manual check;manual_check;manual;False;Manual check;\r\n"
        assert content == expected_csv
