from unittest import mock

from prowler.providers.m365.services.defenderxdr.defenderxdr_service import (
    PendingCAMApproval,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defenderxdr_critical_asset_management_pending_approvals:
    """Tests for the defenderxdr_critical_asset_management_pending_approvals check."""

    def test_api_failed_missing_permission(self):
        """Test FAIL when API call fails (None): missing ThreatHunting.Read.All permission."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.pending_cam_approvals = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals import (
                defenderxdr_critical_asset_management_pending_approvals,
            )

            check = defenderxdr_critical_asset_management_pending_approvals()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Unable to query Critical Asset Management" in result[0].status_extended
            )
            assert "ThreatHunting.Read.All" in result[0].status_extended
            assert result[0].resource_id == "criticalAssetManagement"

    def test_no_pending_approvals_pass(self):
        """Test PASS scenario when there are no pending CAM approvals."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.pending_cam_approvals = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals import (
                defenderxdr_critical_asset_management_pending_approvals,
            )

            check = defenderxdr_critical_asset_management_pending_approvals()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No pending approvals for Critical Asset Management classifications are found."
            )
            assert result[0].resource_name == "Critical Asset Management"
            assert result[0].resource_id == "criticalAssetManagement"
            assert result[0].resource == {}

    def test_single_pending_approval_fail(self):
        """Test FAIL scenario when there is one pending CAM approval."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.pending_cam_approvals = [
            PendingCAMApproval(
                classification="HighValue",
                pending_count=2,
                assets=["server-01", "server-02"],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals import (
                defenderxdr_critical_asset_management_pending_approvals,
            )

            check = defenderxdr_critical_asset_management_pending_approvals()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Critical Asset Management classification 'HighValue' has 2 asset(s) pending approval: server-01, server-02."
            )
            assert result[0].resource_name == "CAM Classification: HighValue"
            assert result[0].resource_id == "cam/HighValue"
            assert (
                result[0].resource == defenderxdr_client.pending_cam_approvals[0].dict()
            )

    def test_multiple_pending_approvals_fail(self):
        """Test FAIL scenario when there are multiple pending CAM approvals."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.pending_cam_approvals = [
            PendingCAMApproval(
                classification="HighValue",
                pending_count=1,
                assets=["server-01"],
            ),
            PendingCAMApproval(
                classification="Critical",
                pending_count=3,
                assets=["db-01", "db-02", "db-03"],
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals import (
                defenderxdr_critical_asset_management_pending_approvals,
            )

            check = defenderxdr_critical_asset_management_pending_approvals()
            result = check.execute()

            assert len(result) == 2

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Critical Asset Management classification 'HighValue' has 1 asset(s) pending approval: server-01."
            )
            assert result[0].resource_name == "CAM Classification: HighValue"
            assert result[0].resource_id == "cam/HighValue"

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Critical Asset Management classification 'Critical' has 3 asset(s) pending approval: db-01, db-02, db-03."
            )
            assert result[1].resource_name == "CAM Classification: Critical"
            assert result[1].resource_id == "cam/Critical"

    def test_pending_approval_with_more_than_five_assets_fail(self):
        """Test FAIL scenario with more than 5 assets to verify truncation."""
        defenderxdr_client = mock.MagicMock()
        defenderxdr_client.audited_tenant = "audited_tenant"
        defenderxdr_client.audited_domain = DOMAIN
        defenderxdr_client.pending_cam_approvals = [
            PendingCAMApproval(
                classification="HighValue",
                pending_count=7,
                assets=[
                    "server-01",
                    "server-02",
                    "server-03",
                    "server-04",
                    "server-05",
                    "server-06",
                    "server-07",
                ],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_client",
                new=defenderxdr_client,
            ),
        ):
            from prowler.providers.m365.services.defenderxdr.defenderxdr_critical_asset_management_pending_approvals.defenderxdr_critical_asset_management_pending_approvals import (
                defenderxdr_critical_asset_management_pending_approvals,
            )

            check = defenderxdr_critical_asset_management_pending_approvals()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Critical Asset Management classification 'HighValue' has 7 asset(s) pending approval: server-01, server-02, server-03, server-04, server-05 and 2 more."
            )
            assert result[0].resource_name == "CAM Classification: HighValue"
            assert result[0].resource_id == "cam/HighValue"
