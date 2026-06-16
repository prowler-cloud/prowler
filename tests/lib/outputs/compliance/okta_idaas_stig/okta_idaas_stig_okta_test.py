from datetime import datetime
from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.okta_idaas_stig.models import OktaIDaaSSTIGModel
from prowler.lib.outputs.compliance.okta_idaas_stig.okta_idaas_stig_okta import (
    OktaIDaaSSTIG,
)
from tests.lib.outputs.compliance.fixtures import OKTA_IDAAS_STIG_OKTA
from tests.lib.outputs.fixtures.fixtures import generate_finding_output

OKTA_ORG_DOMAIN = "dev-12345.okta.com"


class TestOktaIDaaSSTIG:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                provider="okta",
                account_uid=OKTA_ORG_DOMAIN,
                account_name=OKTA_ORG_DOMAIN,
                region="global",
                service_name="signon",
                check_id="signon_global_session_idle_timeout_15min",
                resource_uid="okta-global-session-policy",
                resource_name="Default Policy",
                compliance={"Okta-IDaaS-STIG-1R2": ["OKTA-APP-000020"]},
            )
        ]

        output = OktaIDaaSSTIG(findings, OKTA_IDAAS_STIG_OKTA)
        output_data = output.data[0]
        assert isinstance(output_data, OktaIDaaSSTIGModel)
        assert output_data.Provider == "okta"
        assert output_data.Framework == OKTA_IDAAS_STIG_OKTA.Framework
        assert output_data.Name == OKTA_IDAAS_STIG_OKTA.Name
        assert output_data.OrganizationDomain == OKTA_ORG_DOMAIN
        assert output_data.Description == OKTA_IDAAS_STIG_OKTA.Description
        assert output_data.Requirements_Id == OKTA_IDAAS_STIG_OKTA.Requirements[0].Id
        assert (
            output_data.Requirements_Name == OKTA_IDAAS_STIG_OKTA.Requirements[0].Name
        )
        assert (
            output_data.Requirements_Description
            == OKTA_IDAAS_STIG_OKTA.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_Section
            == OKTA_IDAAS_STIG_OKTA.Requirements[0].Attributes[0].Section
        )
        assert (
            output_data.Requirements_Attributes_Severity
            == OKTA_IDAAS_STIG_OKTA.Requirements[0].Attributes[0].Severity.value
        )
        assert (
            output_data.Requirements_Attributes_RuleID
            == OKTA_IDAAS_STIG_OKTA.Requirements[0].Attributes[0].RuleID
        )
        assert (
            output_data.Requirements_Attributes_StigID
            == OKTA_IDAAS_STIG_OKTA.Requirements[0].Attributes[0].StigID
        )
        assert (
            output_data.Requirements_Attributes_CCI
            == OKTA_IDAAS_STIG_OKTA.Requirements[0].Attributes[0].CCI
        )
        assert (
            output_data.Requirements_Attributes_CheckText
            == OKTA_IDAAS_STIG_OKTA.Requirements[0].Attributes[0].CheckText
        )
        assert (
            output_data.Requirements_Attributes_FixText
            == OKTA_IDAAS_STIG_OKTA.Requirements[0].Attributes[0].FixText
        )
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == "okta-global-session-policy"
        assert output_data.ResourceName == "Default Policy"
        assert output_data.CheckId == "signon_global_session_idle_timeout_15min"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "okta"
        assert output_data_manual.Framework == OKTA_IDAAS_STIG_OKTA.Framework
        assert output_data_manual.Name == OKTA_IDAAS_STIG_OKTA.Name
        assert output_data_manual.OrganizationDomain == ""
        assert (
            output_data_manual.Requirements_Id
            == OKTA_IDAAS_STIG_OKTA.Requirements[1].Id
        )
        assert (
            output_data_manual.Requirements_Attributes_Severity
            == OKTA_IDAAS_STIG_OKTA.Requirements[1].Attributes[0].Severity.value
        )
        assert (
            output_data_manual.Requirements_Attributes_StigID
            == OKTA_IDAAS_STIG_OKTA.Requirements[1].Attributes[0].StigID
        )
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert output_data_manual.Muted is False

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.okta_idaas_stig.okta_idaas_stig_okta.timestamp",
        "2025-01-01 00:00:00",
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                provider="okta",
                account_uid=OKTA_ORG_DOMAIN,
                account_name=OKTA_ORG_DOMAIN,
                region="global",
                service_name="signon",
                check_id="signon_global_session_idle_timeout_15min",
                resource_uid="okta-global-session-policy",
                resource_name="Default Policy",
                compliance={"Okta-IDaaS-STIG-1R2": ["OKTA-APP-000020"]},
            )
        ]
        output = OktaIDaaSSTIG(findings, OKTA_IDAAS_STIG_OKTA)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        expected_csv = f"PROVIDER;DESCRIPTION;ORGANIZATIONDOMAIN;ASSESSMENTDATE;REQUIREMENTS_ID;REQUIREMENTS_NAME;REQUIREMENTS_DESCRIPTION;REQUIREMENTS_ATTRIBUTES_SECTION;REQUIREMENTS_ATTRIBUTES_SEVERITY;REQUIREMENTS_ATTRIBUTES_RULEID;REQUIREMENTS_ATTRIBUTES_STIGID;REQUIREMENTS_ATTRIBUTES_CCI;REQUIREMENTS_ATTRIBUTES_CHECKTEXT;REQUIREMENTS_ATTRIBUTES_FIXTEXT;STATUS;STATUSEXTENDED;RESOURCEID;RESOURCENAME;CHECKID;MUTED;FRAMEWORK;NAME\r\nokta;Defense Information Systems Agency (DISA) Security Technical Implementation Guide (STIG) for Okta Identity as a Service (IDaaS).;{OKTA_ORG_DOMAIN};{datetime.now()};OKTA-APP-000020;Okta must log out a session after a 15-minute period of inactivity.;A session timeout lock is a temporary action taken when a user stops work and moves away from the immediate vicinity of the information system.;CAT II (Medium);medium;SV-273186r1098825_rule;OKTA-APP-000020;['CCI-000057', 'CCI-001133'];Verify the Global Session Policy logs out a session after 15 minutes of inactivity.;From the Admin Console configure the Global Session Policy idle timeout to 15 minutes.;PASS;;okta-global-session-policy;Default Policy;signon_global_session_idle_timeout_15min;False;Okta-IDaaS-STIG;DISA Okta Identity as a Service (IDaaS) STIG V1R2\r\nokta;Defense Information Systems Agency (DISA) Security Technical Implementation Guide (STIG) for Okta Identity as a Service (IDaaS).;;{datetime.now()};OKTA-APP-000650;Okta must enforce a minimum 15-character password length.;The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.;CAT II (Medium);medium;SV-273209r1098894_rule;OKTA-APP-000650;['CCI-000205'];Verify the password policy enforces a minimum length of 15 characters.;From the Admin Console set the minimum password length to 15 characters.;MANUAL;Manual check;manual_check;Manual check;manual;False;Okta-IDaaS-STIG;DISA Okta Identity as a Service (IDaaS) STIG V1R2\r\n"

        assert content == expected_csv
