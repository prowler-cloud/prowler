from unittest import mock
from uuid import uuid4

from azure.mgmt.sql.models import (
    ServerVulnerabilityAssessment,
    VulnerabilityAssessmentRecurringScansProperties,
)

from prowler.providers.azure.services.sqlserver.sqlserver_service import Server
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_sqlserver_va_scan_reports_configured:
    def test_no_sql_servers(self):
        sqlserver_client = mock.MagicMock
        sqlserver_client.sql_servers = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured import (
                sqlserver_va_scan_reports_configured,
            )

            check = sqlserver_va_scan_reports_configured()
            result = check.execute()
            assert len(result) == 0

    def test_sql_servers_no_vulnerability_assessment(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    vulnerability_assessment=None,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured import (
                sqlserver_va_scan_reports_configured,
            )

            check = sqlserver_va_scan_reports_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} has vulnerability assessment disabled."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_no_vulnerability_assessment_emails(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    vulnerability_assessment=ServerVulnerabilityAssessment(
                        storage_container_path="/subcription_id/resource_group/sql_server",
                        recurring_scans=VulnerabilityAssessmentRecurringScansProperties(
                            emails=None, email_subscription_admins=False
                        ),
                    ),
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured import (
                sqlserver_va_scan_reports_configured,
            )

            check = sqlserver_va_scan_reports_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} has vulnerability assessment enabled but no scan reports configured."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_vulnerability_assessment_emails_none(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    vulnerability_assessment=ServerVulnerabilityAssessment(
                        storage_container_path="/subcription_id/resource_group/sql_server",
                        recurring_scans=VulnerabilityAssessmentRecurringScansProperties(
                            emails=None, email_subscription_admins=True
                        ),
                    ),
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured import (
                sqlserver_va_scan_reports_configured,
            )

            check = sqlserver_va_scan_reports_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} has vulnerability assessment enabled and scan reports configured."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_vulnerability_assessment_no_email_subscription_admins(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    vulnerability_assessment=ServerVulnerabilityAssessment(
                        storage_container_path="/subcription_id/resource_group/sql_server",
                        recurring_scans=VulnerabilityAssessmentRecurringScansProperties(
                            emails=["email@email.com"], email_subscription_admins=False
                        ),
                    ),
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured import (
                sqlserver_va_scan_reports_configured,
            )

            check = sqlserver_va_scan_reports_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} has vulnerability assessment enabled and scan reports configured."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"

    def test_sql_servers_vulnerability_assessment_both_emails(self):
        sqlserver_client = mock.MagicMock
        sql_server_name = "SQL Server Name"
        sql_server_id = str(uuid4())
        sqlserver_client.sql_servers = {
            AZURE_SUBSCRIPTION_ID: [
                Server(
                    id=sql_server_id,
                    name=sql_server_name,
                    location="location",
                    public_network_access="",
                    minimal_tls_version="",
                    administrators=None,
                    auditing_policies=None,
                    firewall_rules=None,
                    databases=None,
                    encryption_protector=None,
                    vulnerability_assessment=ServerVulnerabilityAssessment(
                        storage_container_path="/subcription_id/resource_group/sql_server",
                        recurring_scans=VulnerabilityAssessmentRecurringScansProperties(
                            emails=["email@email.com"], email_subscription_admins=True
                        ),
                    ),
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured.sqlserver_client",
            new=sqlserver_client,
        ):
            from prowler.providers.azure.services.sqlserver.sqlserver_va_scan_reports_configured.sqlserver_va_scan_reports_configured import (
                sqlserver_va_scan_reports_configured,
            )

            check = sqlserver_va_scan_reports_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SQL Server {sql_server_name} from subscription {AZURE_SUBSCRIPTION_ID} has vulnerability assessment enabled and scan reports configured."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == sql_server_name
            assert result[0].resource_id == sql_server_id
            assert result[0].location == "location"
