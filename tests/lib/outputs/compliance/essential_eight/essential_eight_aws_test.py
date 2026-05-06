from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.essential_eight.essential_eight_aws import (
    EssentialEightAWS,
)
from prowler.lib.outputs.compliance.essential_eight.models import (
    EssentialEightAWSModel,
)
from tests.lib.outputs.compliance.fixtures import ESSENTIAL_EIGHT_AWS
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

# The fixture's first Requirement maps clause "E8-1.8" (Patch applications,
# clause 8: removal of unsupported online services). The second Requirement is
# E8-6.1 (Restrict Office macros, clause 1) which has no Checks and is therefore
# emitted as a manual row.
COMPLIANCE_NAME = "Essential-Eight-Nov 2023"


class TestEssentialEightAWS:
    def test_output_transform(self):
        findings = [generate_finding_output(compliance={COMPLIANCE_NAME: "E8-1.8"})]

        output = EssentialEightAWS(findings, ESSENTIAL_EIGHT_AWS)
        output_data = output.data[0]
        assert isinstance(output_data, EssentialEightAWSModel)
        assert output_data.Provider == "aws"
        assert output_data.Framework == ESSENTIAL_EIGHT_AWS.Framework
        assert output_data.Name == ESSENTIAL_EIGHT_AWS.Name
        assert output_data.Description == ESSENTIAL_EIGHT_AWS.Description
        assert output_data.AccountId == AWS_ACCOUNT_NUMBER
        assert output_data.Region == AWS_REGION_EU_WEST_1
        assert output_data.Requirements_Id == "E8-1.8"
        assert (
            output_data.Requirements_Description
            == ESSENTIAL_EIGHT_AWS.Requirements[0].Description
        )
        assert output_data.Requirements_Attributes_Section == "1 Patch applications"
        assert output_data.Requirements_Attributes_MaturityLevel == "ML1"
        assert output_data.Requirements_Attributes_AssessmentStatus == "Automated"
        assert output_data.Requirements_Attributes_CloudApplicability == "full"
        assert (
            output_data.Requirements_Attributes_MitigatedThreats
            == "Use of unsupported software, Long-tail vulnerability accumulation"
        )
        assert (
            output_data.Requirements_Attributes_Description
            == ESSENTIAL_EIGHT_AWS.Requirements[0].Attributes[0].Description
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "service_test_check_id"
        assert not output_data.Muted

    def test_manual_requirement(self):
        findings = [generate_finding_output(compliance={COMPLIANCE_NAME: "E8-1.8"})]
        output = EssentialEightAWS(findings, ESSENTIAL_EIGHT_AWS)

        # E8-6.1 (macros) has no Checks -> emitted as a manual row, non-applicable
        manual_rows = [row for row in output.data if row.Status == "MANUAL"]
        assert len(manual_rows) == 1

        manual = manual_rows[0]
        assert manual.Provider == "aws"
        assert manual.AccountId == ""
        assert manual.Region == ""
        assert manual.Requirements_Id == "E8-6.1"
        assert (
            manual.Requirements_Attributes_Section
            == "6 Restrict Microsoft Office macros"
        )
        assert manual.Requirements_Attributes_MaturityLevel == "ML1"
        assert manual.Requirements_Attributes_AssessmentStatus == "Manual"
        assert manual.Requirements_Attributes_CloudApplicability == "non-applicable"
        assert (
            manual.Requirements_Attributes_MitigatedThreats
            == "Macro-based malware delivery"
        )
        assert manual.StatusExtended == "Manual check"
        assert manual.ResourceId == "manual_check"
        assert manual.ResourceName == "Manual check"
        assert manual.CheckId == "manual"
        assert not manual.Muted

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.essential_eight.essential_eight_aws.timestamp",
        "2025-01-01 00:00:00",
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [generate_finding_output(compliance={COMPLIANCE_NAME: "E8-1.8"})]
        output = EssentialEightAWS(findings, ESSENTIAL_EIGHT_AWS)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()

        # Validate header carries the E8-specific column names
        first_line = content.split("\r\n", 1)[0]
        for column in (
            "REQUIREMENTS_ATTRIBUTES_MATURITYLEVEL",
            "REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS",
            "REQUIREMENTS_ATTRIBUTES_CLOUDAPPLICABILITY",
            "REQUIREMENTS_ATTRIBUTES_MITIGATEDTHREATS",
            "REQUIREMENTS_ATTRIBUTES_RATIONALESTATEMENT",
            "REQUIREMENTS_ATTRIBUTES_REMEDIATIONPROCEDURE",
            "REQUIREMENTS_ATTRIBUTES_AUDITPROCEDURE",
        ):
            assert column in first_line, f"missing column {column} in CSV header"

        # rows: header + matched + manual
        rows = [r for r in content.split("\r\n") if r]
        assert len(rows) == 3
        assert rows[1].split(";")[0] == "aws"
        assert "ML1" in rows[1]
        assert ";PASS;" in rows[1]
        assert ";MANUAL;" in rows[2]
        assert ";manual_check;" in rows[2]
