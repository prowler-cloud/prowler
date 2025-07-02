from datetime import datetime
from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreAWSModel,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_aws import (
    ProwlerThreatScoreAWS,
)
from tests.lib.outputs.compliance.fixtures import PROWLER_THREATSCORE_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestProwlerThreatScoreAWS:
    def test_output_transform(self):
        findings = [
            generate_finding_output(compliance={"ProwlerThreatScore-1.0": "1.1.1"})
        ]

        output = ProwlerThreatScoreAWS(findings, PROWLER_THREATSCORE_AWS)
        output_data = output.data[0]
        assert isinstance(output_data, ProwlerThreatScoreAWSModel)
        assert output_data.Provider == "aws"
        assert output_data.Description == PROWLER_THREATSCORE_AWS.Description
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Requirements_Id == PROWLER_THREATSCORE_AWS.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == PROWLER_THREATSCORE_AWS.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Title
            == PROWLER_THREATSCORE_AWS.Requirements[0].Attributes[0].Title
        )
        assert (
            output_data.Requirements_Attributes_Section
            == PROWLER_THREATSCORE_AWS.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_SubSection
            == PROWLER_THREATSCORE_AWS.Requirements[0].Attributes[0].SubSection
        )
        assert (
            output_data.Requirements_Attributes_AttributeDescription
            == PROWLER_THREATSCORE_AWS.Requirements[0]
            .Attributes[0]
            .AttributeDescription
        )
        assert (
            output_data.Requirements_Attributes_AdditionalInformation
            == PROWLER_THREATSCORE_AWS.Requirements[0]
            .Attributes[0]
            .AdditionalInformation
        )
        assert (
            output_data.Requirements_Attributes_LevelOfRisk
            == PROWLER_THREATSCORE_AWS.Requirements[0].Attributes[0].LevelOfRisk
        )
        assert (
            output_data.Requirements_Attributes_Weight
            == PROWLER_THREATSCORE_AWS.Requirements[0].Attributes[0].Weight
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "test-check-id"
        assert not output_data.Muted
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "aws"
        assert output_data_manual.AccountId == ""
        assert output_data_manual.Region == ""
        assert (
            output_data_manual.Requirements_Id
            == PROWLER_THREATSCORE_AWS.Requirements[1].Id
        )
        assert (
            output_data_manual.Requirements_Description
            == PROWLER_THREATSCORE_AWS.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Title
            == PROWLER_THREATSCORE_AWS.Requirements[1].Attributes[0].Title
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == PROWLER_THREATSCORE_AWS.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_SubSection
            == PROWLER_THREATSCORE_AWS.Requirements[1].Attributes[0].SubSection
        )
        assert (
            output_data_manual.Requirements_Attributes_AttributeDescription
            == PROWLER_THREATSCORE_AWS.Requirements[1]
            .Attributes[0]
            .AttributeDescription
        )
        assert (
            output_data_manual.Requirements_Attributes_AdditionalInformation
            == PROWLER_THREATSCORE_AWS.Requirements[1]
            .Attributes[0]
            .AdditionalInformation
        )
        assert (
            output_data_manual.Requirements_Attributes_LevelOfRisk
            == PROWLER_THREATSCORE_AWS.Requirements[1].Attributes[0].LevelOfRisk
        )
        assert (
            output_data_manual.Requirements_Attributes_Weight
            == PROWLER_THREATSCORE_AWS.Requirements[1].Attributes[0].Weight
        )
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert not output_data_manual.Muted

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_aws.timestamp",
        "2025-01-01 00:00:00",
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(compliance={"ProwlerThreatScore-1.0": "1.1.1"})
        ]
        output = ProwlerThreatScoreAWS(findings, PROWLER_THREATSCORE_AWS)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;ACCOUNTID;REGION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_TITLE;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_SUBSECTION;REQUIREMENTS_ATTRIBUTES_ATTRIBUTEDESCRIPTION;REQUIREMENTS_ATTRIBUTES_ADDITIONALINFORMATION;REQUIREMENTS_ATTRIBUTES_LEVELOFRISK;REQUIREMENTS_ATTRIBUTES_WEIGHT;STATUS;STATUSEXTENDED;RESOURCEID;RESOURCENAME;CHECKID;MUTED\r\naws;Prowler ThreatScore Compliance Framework for AWS ensures that the AWS account is compliant taking into account four main pillars: Identity and Access Management, Attack Surface, Forensic Readiness and Encryption;123456789012;eu-west-1;{datetime.now()};1.1.1;Ensure MFA is enabled for the 'root' user account;MFA enabled for 'root';1. IAM;1.1 Authentication;The root user account holds the highest level of privileges within an AWS account. Enabling Multi-Factor Authentication (MFA) enhances security by adding an additional layer of protection beyond just a username and password. With MFA activated, users must provide their credentials (username and password) along with a unique authentication code generated by their AWS MFA device when signing into an AWS website.;Enabling MFA enhances console security by requiring the authenticating user to both possess a time-sensitive key-generating device and have knowledge of their credentials.;5;1000;PASS;;;;test-check-id;False\r\naws;Prowler ThreatScore Compliance Framework for AWS ensures that the AWS account is compliant taking into account four main pillars: Identity and Access Management, Attack Surface, Forensic Readiness and Encryption;;;{datetime.now()};1.1.2;Ensure hardware MFA is enabled for the 'root' user account;CloudTrail logging enabled;1. IAM;1.1 Authentication;The root user account in AWS has the highest level of privileges. Multi-Factor Authentication (MFA) enhances security by adding an extra layer of protection beyond a username and password. When MFA is enabled, users must enter their credentials along with a unique authentication code generated by their AWS MFA device when signing into an AWS website.;A hardware MFA has a smaller attack surface compared to a virtual MFA. Unlike a virtual MFA, which relies on a mobile device that may be vulnerable to malware or compromise, a hardware MFA operates independently, reducing exposure to potential security threats.;3;10;MANUAL;Manual check;manual_check;Manual check;manual;False\r\n"
        assert content == expected_csv
