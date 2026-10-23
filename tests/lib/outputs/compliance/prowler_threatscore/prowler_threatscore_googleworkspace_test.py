from datetime import datetime
from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreGoogleWorkspaceModel,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_googleworkspace import (
    ProwlerThreatScoreGoogleWorkspace,
)
from tests.lib.outputs.compliance.fixtures import PROWLER_THREATSCORE_GOOGLEWORKSPACE
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.googleworkspace.googleworkspace_fixtures import DOMAIN


class TestProwlerThreatScoreGoogleWorkspace:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                compliance={"ProwlerThreatScore-1.0": "1.1.1"},
                provider="googleworkspace",
                account_name=DOMAIN,
                account_uid=DOMAIN,
                region="",
            )
        ]

        output = ProwlerThreatScoreGoogleWorkspace(
            findings, PROWLER_THREATSCORE_GOOGLEWORKSPACE
        )
        output_data = output.data[0]
        assert isinstance(output_data, ProwlerThreatScoreGoogleWorkspaceModel)
        assert output_data.Provider == "googleworkspace"
        assert output_data.Framework == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Framework
        assert output_data.Name == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Name
        assert (
            output_data.Description == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Description
        )
        assert output_data.Domain == DOMAIN
        assert (
            output_data.Requirements_Id
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[0].Id
        )
        assert (
            output_data.Requirements_Description
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Title
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[0].Attributes[0].Title
        )
        assert (
            output_data.Requirements_Attributes_Section
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_SubSection
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[0]
            .Attributes[0]
            .SubSection
        )
        assert (
            output_data.Requirements_Attributes_AttributeDescription
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[0]
            .Attributes[0]
            .AttributeDescription
        )
        assert (
            output_data.Requirements_Attributes_AdditionalInformation
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[0]
            .Attributes[0]
            .AdditionalInformation
        )
        assert (
            output_data.Requirements_Attributes_LevelOfRisk
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[0]
            .Attributes[0]
            .LevelOfRisk
        )
        assert (
            output_data.Requirements_Attributes_Weight
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[0].Attributes[0].Weight
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "service_test_check_id"
        assert not output_data.Muted
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "googleworkspace"
        assert (
            output_data_manual.Framework
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Framework
        )
        assert output_data_manual.Name == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Name
        assert output_data_manual.Domain == ""
        assert (
            output_data_manual.Requirements_Id
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[1].Id
        )
        assert (
            output_data_manual.Requirements_Description
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Title
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[1].Attributes[0].Title
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_SubSection
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[1]
            .Attributes[0]
            .SubSection
        )
        assert (
            output_data_manual.Requirements_Attributes_AttributeDescription
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[1]
            .Attributes[0]
            .AttributeDescription
        )
        assert (
            output_data_manual.Requirements_Attributes_AdditionalInformation
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[1]
            .Attributes[0]
            .AdditionalInformation
        )
        assert (
            output_data_manual.Requirements_Attributes_LevelOfRisk
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[1]
            .Attributes[0]
            .LevelOfRisk
        )
        assert (
            output_data_manual.Requirements_Attributes_Weight
            == PROWLER_THREATSCORE_GOOGLEWORKSPACE.Requirements[1].Attributes[0].Weight
        )
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert not output_data_manual.Muted

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_googleworkspace.timestamp",
        "2025-01-01 00:00:00",
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                compliance={"ProwlerThreatScore-1.0": "1.1.1"},
                provider="googleworkspace",
            )
        ]
        output = ProwlerThreatScoreGoogleWorkspace(
            findings, PROWLER_THREATSCORE_GOOGLEWORKSPACE
        )
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;DOMAIN;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_TITLE;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_SUBSECTION;REQUIREMENTS_ATTRIBUTES_ATTRIBUTEDESCRIPTION;REQUIREMENTS_ATTRIBUTES_ADDITIONALINFORMATION;REQUIREMENTS_ATTRIBUTES_LEVELOFRISK;REQUIREMENTS_ATTRIBUTES_WEIGHT;STATUS;STATUSEXTENDED;RESOURCEID;RESOURCENAME;CHECKID;MUTED;FRAMEWORK;NAME\r\ngoogleworkspace;Prowler ThreatScore Compliance Framework for Google Workspace ensures that the Google Workspace tenant is compliant taking into account four main pillars: Identity and Access Management, Attack Surface, Forensic Readiness and Encryption;123456789012;{datetime.now()};1.1.1;The domain-level policy enforces 2-Step Verification (Multi-Factor Authentication) for all users.;2-Step Verification is enforced for all users;1. IAM;1.1 Authentication;The domain-level policy enforces 2-Step Verification (Multi-Factor Authentication) for all users. 2-Step Verification requires users to present a second form of authentication beyond their password, significantly reducing the risk of account compromise.;Without 2-Step Verification enforcement, users can access their accounts with only a password. If credentials are compromised through phishing, credential stuffing, or data breaches, attackers gain immediate access to the user's account and organizational data without any additional verification.;5;1000;PASS;;;;service_test_check_id;False;ProwlerThreatScore;Prowler ThreatScore Compliance Framework for Google Workspace\r\ngoogleworkspace;Prowler ThreatScore Compliance Framework for Google Workspace ensures that the Google Workspace tenant is compliant taking into account four main pillars: Identity and Access Management, Attack Surface, Forensic Readiness and Encryption;;{datetime.now()};1.1.2;POP and IMAP allow users to access Gmail through legacy or third-party email clients.;POP and IMAP access is disabled for all users;1. IAM;1.1 Authentication;POP and IMAP allow users to access Gmail through legacy or third-party email clients that may not support modern authentication mechanisms such as multifactor authentication. Disabling these protocols forces users to access email through approved clients only.;With POP and IMAP enabled, users can access email through legacy clients that rely on simple password authentication, bypassing multifactor authentication and other modern security controls. This significantly increases the risk of credential-based account compromise.;5;1000;MANUAL;Manual check;manual_check;Manual check;manual;False;ProwlerThreatScore;Prowler ThreatScore Compliance Framework for Google Workspace\r\n"

        assert content == expected_csv
