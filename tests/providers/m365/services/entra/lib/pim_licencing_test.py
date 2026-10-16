"""Tests for the PIM licencing helper."""

from prowler.providers.m365.services.entra.entra_service import SubscribedSku
from prowler.providers.m365.services.entra.lib.pim_licencing import has_pim_licence


class Test_has_pim_licence:
    """Tests for PIM licence detection."""

    def test_none_skus_returns_none(self):
        """Return None when SKUs could not be read."""
        assert has_pim_licence(None) is None

    def test_empty_skus_returns_false(self):
        """Return False when no SKUs exist."""
        assert has_pim_licence([]) is False

    def test_p2_sku_returns_true(self):
        """Return True when AAD_PREMIUM_P2 plan is present and enabled."""
        sku = SubscribedSku(
            sku_id="s1",
            capability_status="Enabled",
            service_plan_names=["AAD_PREMIUM_P2"],
        )
        assert has_pim_licence([sku]) is True

    def test_governance_sku_returns_true(self):
        """Return True when ENTRA_ID_GOVERNANCE plan is present."""
        sku = SubscribedSku(
            sku_id="s1",
            capability_status="Enabled",
            service_plan_names=["ENTRA_ID_GOVERNANCE"],
        )
        assert has_pim_licence([sku]) is True

    def test_disabled_p2_returns_false(self):
        """Return False when P2 SKU is not enabled."""
        sku = SubscribedSku(
            sku_id="s1",
            capability_status="Suspended",
            service_plan_names=["AAD_PREMIUM_P2"],
        )
        assert has_pim_licence([sku]) is False

    def test_no_pim_plans_returns_false(self):
        """Return False when no PIM-related plans exist."""
        sku = SubscribedSku(
            sku_id="s1",
            capability_status="Enabled",
            service_plan_names=["EXCHANGE_S_STANDARD"],
        )
        assert has_pim_licence([sku]) is False

    def test_multiple_skus_p2_in_second(self):
        """Return True when P2 is in a later SKU."""
        skus = [
            SubscribedSku(
                sku_id="s1",
                capability_status="Enabled",
                service_plan_names=["EXCHANGE_S_STANDARD"],
            ),
            SubscribedSku(
                sku_id="s2",
                capability_status="Enabled",
                service_plan_names=["AAD_PREMIUM_P2", "OTHER_PLAN"],
            ),
        ]
        assert has_pim_licence(skus) is True
