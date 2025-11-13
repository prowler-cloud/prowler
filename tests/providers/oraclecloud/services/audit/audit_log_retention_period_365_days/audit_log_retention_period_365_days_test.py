from unittest import mock

from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)


class Test_audit_log_retention_period_365_days:
    def test_no_resources(self):
        """audit_log_retention_period_365_days: No audit configuration"""
        audit_client = mock.MagicMock()
        audit_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        audit_client.audited_tenancy = OCI_TENANCY_ID
        audit_client.configuration = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.audit.audit_log_retention_period_365_days.audit_log_retention_period_365_days.audit_client",
                new=audit_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.audit.audit_log_retention_period_365_days.audit_log_retention_period_365_days import (
                audit_log_retention_period_365_days,
            )

            check = audit_log_retention_period_365_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not found" in result[0].status_extended

    def test_resource_compliant(self):
        """audit_log_retention_period_365_days: Retention period >= 365 days"""
        audit_client = mock.MagicMock()
        audit_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        audit_client.audited_tenancy = OCI_TENANCY_ID

        # Mock audit configuration with compliant retention period
        config = mock.MagicMock()
        config.retention_period_days = 365

        audit_client.configuration = config

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.audit.audit_log_retention_period_365_days.audit_log_retention_period_365_days.audit_client",
                new=audit_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.audit.audit_log_retention_period_365_days.audit_log_retention_period_365_days import (
                audit_log_retention_period_365_days,
            )

            check = audit_log_retention_period_365_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "365 days or greater" in result[0].status_extended

    def test_resource_non_compliant(self):
        """audit_log_retention_period_365_days: Retention period < 365 days"""
        audit_client = mock.MagicMock()
        audit_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        audit_client.audited_tenancy = OCI_TENANCY_ID

        # Mock audit configuration with non-compliant retention period
        config = mock.MagicMock()
        config.retention_period_days = 90

        audit_client.configuration = config

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.audit.audit_log_retention_period_365_days.audit_log_retention_period_365_days.audit_client",
                new=audit_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.audit.audit_log_retention_period_365_days.audit_log_retention_period_365_days import (
                audit_log_retention_period_365_days,
            )

            check = audit_log_retention_period_365_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "less than 365 days" in result[0].status_extended
