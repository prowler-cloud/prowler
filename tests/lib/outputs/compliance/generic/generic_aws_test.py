from datetime import datetime
from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.check.compliance_models import (
    Compliance,
    Compliance_Requirement,
    Generic_Compliance_Requirement_Attribute,
    ISO27001_2013_Requirement_Attribute,
)
from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.compliance.generic.models import GenericComplianceModel
from tests.lib.outputs.compliance.fixtures import NIST_800_53_REVISION_4_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class TestAWSGenericCompliance:
    def test_output_transform(self):
        findings = [
            generate_finding_output(compliance={"NIST-800-53-Revision-4": "ac_2_4"})
        ]

        output = GenericCompliance(findings, NIST_800_53_REVISION_4_AWS)
        output_data = output.data[0]
        assert isinstance(output_data, GenericComplianceModel)
        assert output_data.Provider == "aws"
        assert output_data.Framework == "NIST-800-53-Revision-4"
        assert (
            output_data.Name
            == "National Institute of Standards and Technology (NIST) 800-53 Revision 4"
        )
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Description == NIST_800_53_REVISION_4_AWS.Description
        assert (
            output_data.Requirements_Id == NIST_800_53_REVISION_4_AWS.Requirements[0].Id
        )
        assert (
            output_data.Requirements_Description
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Section
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_SubSection
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].SubSection
        )
        assert (
            output_data.Requirements_Attributes_SubGroup
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].SubGroup
        )
        assert (
            output_data.Requirements_Attributes_Service
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].Service
        )
        assert (
            output_data.Requirements_Attributes_Type
            == NIST_800_53_REVISION_4_AWS.Requirements[0].Attributes[0].Type
        )
        assert output_data.Requirements_Attributes_Comment is None
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "service_test_check_id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "aws"
        assert output_data_manual.Framework == NIST_800_53_REVISION_4_AWS.Framework
        assert output_data_manual.Name == NIST_800_53_REVISION_4_AWS.Name
        assert output_data_manual.AccountId == ""
        assert output_data_manual.Region == ""
        assert output_data_manual.Description == NIST_800_53_REVISION_4_AWS.Description
        assert (
            output_data_manual.Requirements_Id
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Id
        )
        assert (
            output_data_manual.Requirements_Description
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_Section
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].Section
        )
        assert (
            output_data_manual.Requirements_Attributes_SubSection
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].SubSection
        )
        assert (
            output_data_manual.Requirements_Attributes_SubGroup
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].SubGroup
        )
        assert (
            output_data_manual.Requirements_Attributes_Service
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].Service
        )
        assert (
            output_data_manual.Requirements_Attributes_Type
            == NIST_800_53_REVISION_4_AWS.Requirements[1].Attributes[0].Type
        )
        assert output_data_manual.Requirements_Attributes_Comment is None
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert output_data_manual.Muted is False

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.generic.generic.timestamp",
        "2025-01-01 00:00:00",
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(compliance={"NIST-800-53-Revision-4": "ac_2_4"})
        ]
        output = GenericCompliance(findings, NIST_800_53_REVISION_4_AWS)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;ACCOUNTID;REGION;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_SUBSECTION;REQUIREMENTS_ATTRIBUTES_SUBGROUP;REQUIREMENTS_ATTRIBUTES_SERVICE;REQUIREMENTS_ATTRIBUTES_TYPE;STATUS;STATUSEXTENDED;RESOURCEID;CHECKID;MUTED;RESOURCENAME;FRAMEWORK;NAME;REQUIREMENTS_ATTRIBUTES_COMMENT\r\naws;NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.;123456789012;eu-west-1;{datetime.now()};ac_2_4;Account Management;Access Control (AC);Account Management (AC-2);;aws;;PASS;;;service_test_check_id;False;;NIST-800-53-Revision-4;National Institute of Standards and Technology (NIST) 800-53 Revision 4;\r\naws;NIST 800-53 is a regulatory standard that defines the minimum baseline of security controls for all U.S. federal information systems except those related to national security. The controls defined in this standard are customizable and address a diverse set of security and privacy requirements.;;;{datetime.now()};ac_2_5;Account Management;Access Control (AC);Account Management (AC-2);;aws;;MANUAL;Manual check;manual_check;manual;False;Manual check;NIST-800-53-Revision-4;National Institute of Standards and Technology (NIST) 800-53 Revision 4;\r\n"

        assert content == expected_csv

    def test_csv_row_count_matches_framework_checks_not_stored_compliance(self):
        """Regression test for PROWLER-1763.

        Ensures CSV emission is driven by the framework JSON's Requirements[].Checks
        (the same source the UI uses) and not by the per-finding `finding.compliance`
        snapshot stored at scan time. If `finding.check_id` is in a requirement's
        Checks list, the row must be emitted regardless of what was stored in
        `finding.compliance`. Conversely, a stale `finding.compliance` entry pointing
        to a requirement whose Checks list no longer contains the finding's check_id
        must not produce a row.
        """
        framework_name = "Test-Framework-1763"
        compliance = Compliance(
            Framework=framework_name,
            Name=framework_name,
            Provider="AWS",
            Version="",
            Description="Regression fixture for PROWLER-1763",
            Requirements=[
                Compliance_Requirement(
                    Id="req_in_framework",
                    Description="Requirement currently in framework",
                    Attributes=[
                        Generic_Compliance_Requirement_Attribute(
                            Section="Section A", Service="aws"
                        )
                    ],
                    Checks=["service_check_in_framework"],
                ),
                Compliance_Requirement(
                    Id="req_no_longer_in_framework",
                    Description="Requirement whose Checks list no longer includes the finding's check_id",
                    Attributes=[
                        Generic_Compliance_Requirement_Attribute(
                            Section="Section B", Service="aws"
                        )
                    ],
                    Checks=["service_different_check"],
                ),
            ],
        )

        # Snapshot drift case: finding.compliance maps to a requirement whose
        # current Checks list no longer includes the finding's check_id, AND
        # the finding belongs to a requirement that is NOT in the snapshot.
        findings = [
            generate_finding_output(
                check_id="service_check_in_framework",
                compliance={framework_name: ["req_no_longer_in_framework"]},
            )
        ]

        output = GenericCompliance(findings, compliance)
        rows = [
            row
            for row in output.data
            if row.Status != "MANUAL" and row.ResourceName != "Manual check"
        ]
        assert (
            len(rows) == 1
        ), f"Expected 1 row driven by framework JSON, got {len(rows)}"
        assert rows[0].Requirements_Id == "req_in_framework"
        assert rows[0].CheckId == "service_check_in_framework"

    def test_transform_tolerates_framework_specific_attribute_schema(self):
        """GenericCompliance is the documented last-resort renderer, so it must not
        crash on a framework whose attribute schema lacks the universal fields
        (Section, SubSection, SubGroup, Service, Type, Comment). ISO27001 declares
        none of them; missing fields must render as None instead of raising
        AttributeError and dropping the whole CSV."""
        framework_name = "ISO27001-2013-External"
        compliance = Compliance(
            Framework=framework_name,
            Name=framework_name,
            Provider="external",
            Version="",
            Description="Framework shipping a provider-specific attribute schema",
            Requirements=[
                Compliance_Requirement(
                    Id="A.5.1.1",
                    Description="Policies for information security",
                    Attributes=[
                        ISO27001_2013_Requirement_Attribute(
                            Category="Information security policies",
                            Objetive_ID="A.5.1",
                            Objetive_Name="Management direction",
                            Check_Summary="Policy is defined",
                        )
                    ],
                    Checks=["service_test_check_id"],
                )
            ],
        )

        findings = [generate_finding_output(check_id="service_test_check_id")]

        output = GenericCompliance(findings, compliance)

        rows = [row for row in output.data if row.Status != "MANUAL"]
        assert len(rows) == 1
        assert rows[0].Requirements_Id == "A.5.1.1"
        assert rows[0].Requirements_Attributes_Section is None
        assert rows[0].Requirements_Attributes_SubSection is None
        assert rows[0].Requirements_Attributes_SubGroup is None
        assert rows[0].Requirements_Attributes_Service is None
        assert rows[0].Requirements_Attributes_Type is None
        assert rows[0].Requirements_Attributes_Comment is None
