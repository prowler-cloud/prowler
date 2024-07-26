from datetime import datetime
from io import StringIO

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.aws_well_architected.aws_well_architected import (
    AWSWellArchitected,
)
from prowler.lib.outputs.compliance.aws_well_architected.models import (
    AWSWellArchitectedModel,
)
from tests.lib.outputs.compliance.fixtures import AWS_WELL_ARCHITECTED
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestAWSWellArchitected:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                compliance={
                    "AWS-Well-Architected-Framework-Security-Pillar": "SEC01-BP01"
                }
            )
        ]

        output = AWSWellArchitected(findings, AWS_WELL_ARCHITECTED)
        output_data = output.data[0]
        assert isinstance(output_data, AWSWellArchitectedModel)
        assert output_data.Provider == "aws"
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Requirements_Id == AWS_WELL_ARCHITECTED.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == AWS_WELL_ARCHITECTED.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Name
            == AWS_WELL_ARCHITECTED.Requirements[0].Attributes[0].Name
        )
        assert (
            output_data.Requirements_Attributes_WellArchitectedQuestionId
            == AWS_WELL_ARCHITECTED.Requirements[0]
            .Attributes[0]
            .WellArchitectedQuestionId
        )
        assert (
            output_data.Requirements_Attributes_WellArchitectedPracticeId
            == AWS_WELL_ARCHITECTED.Requirements[0]
            .Attributes[0]
            .WellArchitectedPracticeId
        )
        assert (
            output_data.Requirements_Attributes_Section
            == AWS_WELL_ARCHITECTED.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_SubSection
            == AWS_WELL_ARCHITECTED.Requirements[0].Attributes[0].SubSection
        )
        assert (
            output_data.Requirements_Attributes_LevelOfRisk
            == AWS_WELL_ARCHITECTED.Requirements[0].Attributes[0].LevelOfRisk
        )
        assert (
            output_data.Requirements_Attributes_AssessmentMethod
            == AWS_WELL_ARCHITECTED.Requirements[0].Attributes[0].AssessmentMethod
        )
        assert (
            output_data.Requirements_Attributes_Description
            == AWS_WELL_ARCHITECTED.Requirements[0].Attributes[0].Description
        )
        assert (
            output_data.Requirements_Attributes_ImplementationGuidanceUrl
            == AWS_WELL_ARCHITECTED.Requirements[0]
            .Attributes[0]
            .ImplementationGuidanceUrl
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
        assert (
            output_data_manual.Requirements_Id
            == AWS_WELL_ARCHITECTED.Requirements[1].Id
        )
        assert (
            output_data_manual.Requirements_Description
            == AWS_WELL_ARCHITECTED.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Name
            == AWS_WELL_ARCHITECTED.Requirements[1].Attributes[0].Name
        )
        assert (
            output_data_manual.Requirements_Attributes_WellArchitectedQuestionId
            == AWS_WELL_ARCHITECTED.Requirements[1]
            .Attributes[0]
            .WellArchitectedQuestionId
        )
        assert (
            output_data_manual.Requirements_Attributes_WellArchitectedPracticeId
            == AWS_WELL_ARCHITECTED.Requirements[1]
            .Attributes[0]
            .WellArchitectedPracticeId
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == AWS_WELL_ARCHITECTED.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_SubSection
            == AWS_WELL_ARCHITECTED.Requirements[1].Attributes[0].SubSection
        )
        assert (
            output_data_manual.Requirements_Attributes_LevelOfRisk
            == AWS_WELL_ARCHITECTED.Requirements[1].Attributes[0].LevelOfRisk
        )
        assert (
            output_data_manual.Requirements_Attributes_AssessmentMethod
            == AWS_WELL_ARCHITECTED.Requirements[1].Attributes[0].AssessmentMethod
        )
        assert (
            output_data_manual.Requirements_Attributes_Description
            == AWS_WELL_ARCHITECTED.Requirements[1].Attributes[0].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_ImplementationGuidanceUrl
            == AWS_WELL_ARCHITECTED.Requirements[1]
            .Attributes[0]
            .ImplementationGuidanceUrl
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
                compliance={
                    "AWS-Well-Architected-Framework-Security-Pillar": "SEC01-BP01"
                }
            )
        ]
        output = AWSWellArchitected(findings, AWS_WELL_ARCHITECTED)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;ACCOUNTID;REGION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_NAME;REQUIREMENTS_ATTRIBUTES_WELLARCHITECTEDQUESTIONID;REQUIREMENTS_ATTRIBUTES_WELLARCHITECTEDPRACTICEID;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_SUBSECTION;REQUIREMENTS_ATTRIBUTES_LEVELOFRISK;REQUIREMENTS_ATTRIBUTES_ASSESSMENTMETHOD;REQUIREMENTS_ATTRIBUTES_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_IMPLEMENTATIONGUIDANCEURL;STATUS;STATUSEXTENDED;RESOURCEID;CHECKID;MUTED;RESOURCENAME\r\naws;Best Practices for AWS Well-Architected Framework Security Pillar. The focus of this framework is the security pillar of the AWS Well-Architected Framework. It provides guidance to help you apply best practices, current recommendations in the design, delivery, and maintenance of secure AWS workloads.;123456789012;eu-west-1;{datetime.now()};SEC01-BP01;Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.;SEC01-BP01 Separate workloads using accounts;securely-operate;sec_securely_operate_multi_accounts;Security foundations;AWS account management and separation;High;Automated;Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.;https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_multi_accounts.html#implementation-guidance.;PASS;;;test-check-id;False;\r\naws;Best Practices for AWS Well-Architected Framework Security Pillar. The focus of this framework is the security pillar of the AWS Well-Architected Framework. It provides guidance to help you apply best practices, current recommendations in the design, delivery, and maintenance of secure AWS workloads.;;;{datetime.now()};SEC01-BP02;Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.;SEC01-BP01 Separate workloads using accounts;securely-operate;sec_securely_operate_multi_accounts;Security foundations;AWS account management and separation;High;Automated;Establish common guardrails and isolation between environments (such as production, development, and test) and workloads through a multi-account strategy. Account-level separation is strongly recommended, as it provides a strong isolation boundary for security, billing, and access.;https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_multi_accounts.html#implementation-guidance.;MANUAL;Manual check;manual_check;manual;False;Manual check\r\n"
        assert content == expected_csv
