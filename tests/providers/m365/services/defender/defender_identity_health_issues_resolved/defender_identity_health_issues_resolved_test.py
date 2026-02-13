from datetime import datetime
from unittest import mock

from prowler.providers.m365.services.defender.defender_service import (
    HealthIssueStatus,
    HealthIssueSeverity,
    HealthIssueType,
    IdentityHealthIssue,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_identity_health_issues_resolved:
    def test_no_health_issues(self):
        """Test PASS scenario when no health issues exist."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.tenant_domain = DOMAIN
        defender_client.identity_health_issues = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved import (
                defender_identity_health_issues_resolved,
            )

            check = defender_identity_health_issues_resolved()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Microsoft Defender for Identity has no health issues reported."
            )
            assert result[0].resource_name == "Defender for Identity Health"
            assert result[0].resource_id == DOMAIN

    def test_all_issues_closed_pass(self):
        """Test PASS scenario when all health issues are closed."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.tenant_domain = DOMAIN
        defender_client.identity_health_issues = [
            IdentityHealthIssue(
                id="issue-1",
                display_name="Sensor service is not running",
                health_issue_type=HealthIssueType.SENSOR,
                status=HealthIssueStatus.CLOSED,
                severity=HealthIssueSeverity.HIGH,
                description="The sensor service is not running on the domain controller.",
                recommendations=["Start the Azure ATP Sensor service."],
                domain_names=["contoso.local"],
                sensor_dns_names=["DC01.contoso.local"],
                created_date_time=datetime(2024, 1, 15, 10, 0, 0),
                last_modified_date_time=datetime(2024, 1, 15, 12, 0, 0),
                additional_information=[],
                issue_type_id="sensor-service-not-running",
            ),
            IdentityHealthIssue(
                id="issue-2",
                display_name="Directory Services credentials expired",
                health_issue_type=HealthIssueType.GLOBAL,
                status=HealthIssueStatus.CLOSED,
                severity=HealthIssueSeverity.MEDIUM,
                description="The Directory Services account credentials have expired.",
                recommendations=["Update the credentials in the MDI portal."],
                domain_names=["contoso.local"],
                sensor_dns_names=[],
                created_date_time=datetime(2024, 1, 10, 8, 0, 0),
                last_modified_date_time=datetime(2024, 1, 10, 14, 0, 0),
                additional_information=[],
                issue_type_id="ds-credentials-expired",
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved import (
                defender_identity_health_issues_resolved,
            )

            check = defender_identity_health_issues_resolved()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Microsoft Defender for Identity has no open health issues. All issues have been resolved."
            )
            assert result[0].resource_name == "Defender for Identity Health"
            assert result[0].resource_id == DOMAIN

    def test_open_issues_fail(self):
        """Test FAIL scenario when there are open health issues."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.tenant_domain = DOMAIN
        defender_client.identity_health_issues = [
            IdentityHealthIssue(
                id="issue-1",
                display_name="Sensor service is not running",
                health_issue_type=HealthIssueType.SENSOR,
                status=HealthIssueStatus.OPEN,
                severity=HealthIssueSeverity.HIGH,
                description="The sensor service is not running on the domain controller.",
                recommendations=["Start the Azure ATP Sensor service."],
                domain_names=["contoso.local"],
                sensor_dns_names=["DC01.contoso.local"],
                created_date_time=datetime(2024, 1, 15, 10, 0, 0),
                last_modified_date_time=datetime(2024, 1, 15, 12, 0, 0),
                additional_information=[],
                issue_type_id="sensor-service-not-running",
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved import (
                defender_identity_health_issues_resolved,
            )

            check = defender_identity_health_issues_resolved()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Microsoft Defender for Identity has 1 open health issue(s) out of 1 total issue(s) that require attention."
            )
            assert result[0].resource_name == "Defender for Identity Health"
            assert result[0].resource_id == DOMAIN

    def test_multiple_open_issues_fail(self):
        """Test FAIL scenario when there are multiple open health issues."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.tenant_domain = DOMAIN
        defender_client.identity_health_issues = [
            IdentityHealthIssue(
                id="issue-1",
                display_name="Sensor service is not running",
                health_issue_type=HealthIssueType.SENSOR,
                status=HealthIssueStatus.OPEN,
                severity=HealthIssueSeverity.HIGH,
                description="The sensor service is not running on the domain controller.",
                recommendations=["Start the Azure ATP Sensor service."],
                domain_names=["contoso.local"],
                sensor_dns_names=["DC01.contoso.local"],
                created_date_time=datetime(2024, 1, 15, 10, 0, 0),
                last_modified_date_time=datetime(2024, 1, 15, 12, 0, 0),
                additional_information=[],
                issue_type_id="sensor-service-not-running",
            ),
            IdentityHealthIssue(
                id="issue-2",
                display_name="Directory Services credentials expired",
                health_issue_type=HealthIssueType.GLOBAL,
                status=HealthIssueStatus.OPEN,
                severity=HealthIssueSeverity.MEDIUM,
                description="The Directory Services account credentials have expired.",
                recommendations=["Update the credentials in the MDI portal."],
                domain_names=["contoso.local"],
                sensor_dns_names=[],
                created_date_time=datetime(2024, 1, 10, 8, 0, 0),
                last_modified_date_time=datetime(2024, 1, 10, 14, 0, 0),
                additional_information=[],
                issue_type_id="ds-credentials-expired",
            ),
            IdentityHealthIssue(
                id="issue-3",
                display_name="Sensor outdated",
                health_issue_type=HealthIssueType.SENSOR,
                status=HealthIssueStatus.CLOSED,
                severity=HealthIssueSeverity.LOW,
                description="The sensor is outdated and should be updated.",
                recommendations=["Update the sensor to the latest version."],
                domain_names=["contoso.local"],
                sensor_dns_names=["DC02.contoso.local"],
                created_date_time=datetime(2024, 1, 5, 9, 0, 0),
                last_modified_date_time=datetime(2024, 1, 6, 11, 0, 0),
                additional_information=[],
                issue_type_id="sensor-outdated",
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved import (
                defender_identity_health_issues_resolved,
            )

            check = defender_identity_health_issues_resolved()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Microsoft Defender for Identity has 2 open health issue(s) out of 3 total issue(s) that require attention."
            )
            assert result[0].resource_name == "Defender for Identity Health"
            assert result[0].resource_id == DOMAIN

    def test_suppressed_issues_excluded(self):
        """Test that suppressed issues are excluded from the evaluation."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.tenant_domain = DOMAIN
        defender_client.identity_health_issues = [
            IdentityHealthIssue(
                id="issue-1",
                display_name="Sensor service is not running",
                health_issue_type=HealthIssueType.SENSOR,
                status=HealthIssueStatus.SUPPRESSED,
                severity=HealthIssueSeverity.HIGH,
                description="The sensor service is not running on the domain controller.",
                recommendations=["Start the Azure ATP Sensor service."],
                domain_names=["contoso.local"],
                sensor_dns_names=["DC01.contoso.local"],
                created_date_time=datetime(2024, 1, 15, 10, 0, 0),
                last_modified_date_time=datetime(2024, 1, 15, 12, 0, 0),
                additional_information=[],
                issue_type_id="sensor-service-not-running",
            ),
            IdentityHealthIssue(
                id="issue-2",
                display_name="Directory Services credentials expired",
                health_issue_type=HealthIssueType.GLOBAL,
                status=HealthIssueStatus.SUPPRESSED,
                severity=HealthIssueSeverity.MEDIUM,
                description="The Directory Services account credentials have expired.",
                recommendations=["Update the credentials in the MDI portal."],
                domain_names=["contoso.local"],
                sensor_dns_names=[],
                created_date_time=datetime(2024, 1, 10, 8, 0, 0),
                last_modified_date_time=datetime(2024, 1, 10, 14, 0, 0),
                additional_information=[],
                issue_type_id="ds-credentials-expired",
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved import (
                defender_identity_health_issues_resolved,
            )

            check = defender_identity_health_issues_resolved()
            result = check.execute()

            # All issues are suppressed, so treated as no active issues
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Microsoft Defender for Identity has no health issues reported."
            )
            assert result[0].resource_name == "Defender for Identity Health"
            assert result[0].resource_id == DOMAIN

    def test_mixed_suppressed_and_open_issues(self):
        """Test scenario with both suppressed and open issues."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.tenant_domain = DOMAIN
        defender_client.identity_health_issues = [
            IdentityHealthIssue(
                id="issue-1",
                display_name="Sensor service is not running",
                health_issue_type=HealthIssueType.SENSOR,
                status=HealthIssueStatus.SUPPRESSED,
                severity=HealthIssueSeverity.HIGH,
                description="The sensor service is not running on the domain controller.",
                recommendations=["Start the Azure ATP Sensor service."],
                domain_names=["contoso.local"],
                sensor_dns_names=["DC01.contoso.local"],
                created_date_time=datetime(2024, 1, 15, 10, 0, 0),
                last_modified_date_time=datetime(2024, 1, 15, 12, 0, 0),
                additional_information=[],
                issue_type_id="sensor-service-not-running",
            ),
            IdentityHealthIssue(
                id="issue-2",
                display_name="Directory Services credentials expired",
                health_issue_type=HealthIssueType.GLOBAL,
                status=HealthIssueStatus.OPEN,
                severity=HealthIssueSeverity.MEDIUM,
                description="The Directory Services account credentials have expired.",
                recommendations=["Update the credentials in the MDI portal."],
                domain_names=["contoso.local"],
                sensor_dns_names=[],
                created_date_time=datetime(2024, 1, 10, 8, 0, 0),
                last_modified_date_time=datetime(2024, 1, 10, 14, 0, 0),
                additional_information=[],
                issue_type_id="ds-credentials-expired",
            ),
            IdentityHealthIssue(
                id="issue-3",
                display_name="Sensor outdated",
                health_issue_type=HealthIssueType.SENSOR,
                status=HealthIssueStatus.CLOSED,
                severity=HealthIssueSeverity.LOW,
                description="The sensor is outdated and should be updated.",
                recommendations=["Update the sensor to the latest version."],
                domain_names=["contoso.local"],
                sensor_dns_names=["DC02.contoso.local"],
                created_date_time=datetime(2024, 1, 5, 9, 0, 0),
                last_modified_date_time=datetime(2024, 1, 6, 11, 0, 0),
                additional_information=[],
                issue_type_id="sensor-outdated",
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved import (
                defender_identity_health_issues_resolved,
            )

            check = defender_identity_health_issues_resolved()
            result = check.execute()

            # 1 suppressed (excluded), 1 open, 1 closed = 2 active issues, 1 open
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Microsoft Defender for Identity has 1 open health issue(s) out of 2 total issue(s) that require attention."
            )
            assert result[0].resource_name == "Defender for Identity Health"
            assert result[0].resource_id == DOMAIN

    def test_tenant_domain_fallback(self):
        """Test that resource_id falls back to 'defenderIdentity' when tenant_domain is None."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.tenant_domain = None
        defender_client.identity_health_issues = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved import (
                defender_identity_health_issues_resolved,
            )

            check = defender_identity_health_issues_resolved()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "defenderIdentity"

    def test_global_health_issue_type(self):
        """Test with a global health issue type."""
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.tenant_domain = DOMAIN
        defender_client.identity_health_issues = [
            IdentityHealthIssue(
                id="global-issue-1",
                display_name="Directory Services account not configured",
                health_issue_type=HealthIssueType.GLOBAL,
                status=HealthIssueStatus.OPEN,
                severity=HealthIssueSeverity.HIGH,
                description="No Directory Services account has been configured for this workspace.",
                recommendations=[
                    "Configure a Directory Services account in the MDI portal."
                ],
                domain_names=[],
                sensor_dns_names=[],
                created_date_time=datetime(2024, 1, 20, 14, 0, 0),
                last_modified_date_time=datetime(2024, 1, 20, 14, 0, 0),
                additional_information=[],
                issue_type_id="ds-account-not-configured",
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_resolved.defender_identity_health_issues_resolved import (
                defender_identity_health_issues_resolved,
            )

            check = defender_identity_health_issues_resolved()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Microsoft Defender for Identity has 1 open health issue(s) out of 1 total issue(s) that require attention."
            )
            assert result[0].resource_name == "Defender for Identity Health"
            assert result[0].resource_id == DOMAIN
