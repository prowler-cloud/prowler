from unittest import mock

from prowler.providers.m365.services.entra.entra_service import RiskDetection
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_identity_protection_high_risk_detections_triaged:
    def test_no_detections_pass(self):
        """PASS when there are no untriaged high-risk detections."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged import (
                entra_identity_protection_high_risk_detections_triaged,
            )

            entra_client.high_risk_detections = []
            entra_client.high_risk_detections_error = None

            check = entra_identity_protection_high_risk_detections_triaged()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No high-risk Identity Protection detections are pending triage."
            )
            assert result[0].resource_name == "Identity Protection Risk Detections"
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"

    def test_detections_present_fail(self):
        """FAIL when there are untriaged high-risk detections."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged import (
                entra_identity_protection_high_risk_detections_triaged,
            )

            entra_client.high_risk_detections = [
                RiskDetection(
                    id="detection-1",
                    risk_event_type="leakedCredentials",
                    risk_level="high",
                    risk_state="atRisk",
                    user_principal_name="user1@contoso.com",
                    detected_date_time="2026-09-20T08:15:00Z",
                ),
                RiskDetection(
                    id="detection-2",
                    risk_event_type="passwordSpray",
                    risk_level="high",
                    risk_state="atRisk",
                    user_principal_name="user2@contoso.com",
                    detected_date_time="2026-09-21T10:00:00Z",
                ),
            ]
            entra_client.high_risk_detections_error = None

            check = entra_identity_protection_high_risk_detections_triaged()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "2 high-risk Identity Protection detection(s)"
                in result[0].status_extended
            )
            assert "user1@contoso.com" in result[0].status_extended
            assert "user2@contoso.com" in result[0].status_extended
            assert result[0].resource_name == "Identity Protection Risk Detections"
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"

    def test_detections_many_users_truncated(self):
        """FAIL with truncated user list when more than 5 users are affected."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged import (
                entra_identity_protection_high_risk_detections_triaged,
            )

            entra_client.high_risk_detections = [
                RiskDetection(
                    id=f"detection-{i}",
                    risk_event_type="leakedCredentials",
                    risk_level="high",
                    risk_state="atRisk",
                    user_principal_name=f"user{i}@contoso.com",
                )
                for i in range(1, 8)
            ]
            entra_client.high_risk_detections_error = None

            check = entra_identity_protection_high_risk_detections_triaged()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "7 high-risk Identity Protection detection(s)"
                in result[0].status_extended
            )
            assert "and 2 more" in result[0].status_extended
            assert result[0].location == "global"

    def test_error_manual(self):
        """MANUAL when risk detections cannot be retrieved."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged import (
                entra_identity_protection_high_risk_detections_triaged,
            )

            entra_client.high_risk_detections = None
            entra_client.high_risk_detections_error = (
                "Insufficient privileges to read Identity Protection risk detections. "
                "Required permission: IdentityRiskEvent.Read.All."
            )

            check = entra_identity_protection_high_risk_detections_triaged()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Cannot evaluate" in result[0].status_extended
            assert "IdentityRiskEvent.Read.All" in result[0].status_extended
            assert result[0].resource_name == "Identity Protection Risk Detections"
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"

    def test_single_detection_fail(self):
        """FAIL with a single detection for one user."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_identity_protection_high_risk_detections_triaged.entra_identity_protection_high_risk_detections_triaged import (
                entra_identity_protection_high_risk_detections_triaged,
            )

            entra_client.high_risk_detections = [
                RiskDetection(
                    id="detection-1",
                    risk_event_type="anomalousToken",
                    risk_level="high",
                    risk_state="atRisk",
                    user_principal_name="admin@contoso.com",
                    detected_date_time="2026-09-25T12:00:00Z",
                ),
            ]
            entra_client.high_risk_detections_error = None

            check = entra_identity_protection_high_risk_detections_triaged()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "1 high-risk Identity Protection detection(s)"
                in result[0].status_extended
            )
            assert "admin@contoso.com" in result[0].status_extended
            assert result[0].location == "global"
