from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled"


def _make_org(bookings_enabled):
    from prowler.providers.m365.services.admincenter.admincenter_service import (
        Organization,
    )

    return Organization(
        name="test-org",
        guid="org-guid",
        customer_lockbox_enabled=False,
        bookings_enabled=bookings_enabled,
    )


def _make_policy(is_default=True, bookings_mailbox_creation_enabled=True):
    from prowler.providers.m365.services.admincenter.admincenter_service import (
        OwaMailboxPolicy,
    )

    return OwaMailboxPolicy(
        id="OwaMailboxPolicy-Default",
        is_default=is_default,
        bookings_mailbox_creation_enabled=bookings_mailbox_creation_enabled,
    )


class Test_admincenter_shared_bookings_disabled:
    def _run(self, org, policies):
        admincenter_client = mock.MagicMock()
        admincenter_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.admincenter_client", new=admincenter_client
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_shared_bookings_disabled.admincenter_shared_bookings_disabled import (
                admincenter_shared_bookings_disabled,
            )

            admincenter_client.organization_config = org
            admincenter_client.mailbox_policies = policies
            return admincenter_shared_bookings_disabled().execute()

    def test_no_org_config(self):
        assert self._run(None, []) == []

    def test_bookings_enabled_tenant_and_policy(self):
        result = self._run(_make_org(True), [_make_policy()])
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_bookings_disabled_at_tenant(self):
        result = self._run(_make_org(False), [_make_policy()])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Shared Bookings is disabled at the tenant level."
        )

    def test_bookings_disabled_in_default_policy(self):
        result = self._run(
            _make_org(True),
            [_make_policy(bookings_mailbox_creation_enabled=False)],
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Shared Bookings is disabled in the default OWA mailbox policy."
        )
