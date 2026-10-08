from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    CrossTenantAccessDefault,
    CrossTenantB2BSetting,
    CrossTenantTarget,
    CrossTenantTargetConfiguration,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_cross_tenant_access_default_outbound_restricted.entra_cross_tenant_access_default_outbound_restricted"


def _all_users_all_apps_allowed():
    """Return a B2B setting that allows all users and all applications."""
    return CrossTenantB2BSetting(
        users_and_groups=CrossTenantTargetConfiguration(
            access_type="allowed",
            targets=[CrossTenantTarget(target="AllUsers", target_type="user")],
        ),
        applications=CrossTenantTargetConfiguration(
            access_type="allowed",
            targets=[
                CrossTenantTarget(target="AllApplications", target_type="application")
            ],
        ),
    )


def _blocked_setting():
    """Return a B2B setting that blocks all users and all applications."""
    return CrossTenantB2BSetting(
        users_and_groups=CrossTenantTargetConfiguration(
            access_type="blocked",
            targets=[CrossTenantTarget(target="AllUsers", target_type="user")],
        ),
        applications=CrossTenantTargetConfiguration(
            access_type="blocked",
            targets=[
                CrossTenantTarget(target="AllApplications", target_type="application")
            ],
        ),
    )


def _specific_groups_allowed():
    """Return a B2B setting that allows only specific groups and all apps."""
    return CrossTenantB2BSetting(
        users_and_groups=CrossTenantTargetConfiguration(
            access_type="allowed",
            targets=[
                CrossTenantTarget(
                    target="00000000-0000-0000-0000-000000000001",
                    target_type="user",
                )
            ],
        ),
        applications=CrossTenantTargetConfiguration(
            access_type="allowed",
            targets=[
                CrossTenantTarget(target="AllApplications", target_type="application")
            ],
        ),
    )


class Test_entra_cross_tenant_access_default_outbound_restricted:
    def _run(self, policy):
        entra_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_cross_tenant_access_default_outbound_restricted.entra_cross_tenant_access_default_outbound_restricted import (
                entra_cross_tenant_access_default_outbound_restricted,
            )

            entra_client.cross_tenant_access_default = policy
            return entra_cross_tenant_access_default_outbound_restricted().execute()

    def test_no_policy(self):
        """MANUAL when the policy could not be retrieved."""
        result = self._run(None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be read" in result[0].status_extended

    def test_both_blocked_pass(self):
        """PASS when both outbound settings are blocked."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=_blocked_setting(),
                b2b_direct_connect_outbound=_blocked_setting(),
            )
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "restricts outbound access" in result[0].status_extended

    def test_collaboration_outbound_unrestricted_fail(self):
        """FAIL when B2B collaboration outbound allows all users and all apps."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=_all_users_all_apps_allowed(),
                b2b_direct_connect_outbound=_blocked_setting(),
            )
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "B2B collaboration outbound" in result[0].status_extended
        assert "B2B direct connect outbound" not in result[0].status_extended

    def test_direct_connect_outbound_unrestricted_fail(self):
        """FAIL when B2B direct connect outbound allows all users and all apps."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=_blocked_setting(),
                b2b_direct_connect_outbound=_all_users_all_apps_allowed(),
            )
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "B2B direct connect outbound" in result[0].status_extended
        assert "B2B collaboration outbound" not in result[0].status_extended

    def test_both_outbound_unrestricted_fail(self):
        """FAIL when both outbound settings allow all users and all apps."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=_all_users_all_apps_allowed(),
                b2b_direct_connect_outbound=_all_users_all_apps_allowed(),
            )
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "B2B collaboration outbound" in result[0].status_extended
        assert "B2B direct connect outbound" in result[0].status_extended

    def test_specific_groups_allowed_pass(self):
        """PASS when users are scoped to specific groups (not AllUsers)."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=_specific_groups_allowed(),
                b2b_direct_connect_outbound=_blocked_setting(),
            )
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_none_b2b_settings_manual(self):
        """MANUAL when the outbound settings could not be read."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=None,
                b2b_direct_connect_outbound=None,
            )
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_incomplete_setting_with_blocked_setting_manual(self):
        """MANUAL when no setting is open but one has no users and groups data."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=CrossTenantB2BSetting(
                    users_and_groups=None,
                    applications=_blocked_setting().applications,
                ),
                b2b_direct_connect_outbound=_blocked_setting(),
            )
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "incomplete" in result[0].status_extended

    def test_setting_without_targets_manual(self):
        """MANUAL when an access configuration has no targets."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=CrossTenantB2BSetting(
                    users_and_groups=CrossTenantTargetConfiguration(
                        access_type="allowed", targets=[]
                    ),
                    applications=_blocked_setting().applications,
                ),
                b2b_direct_connect_outbound=_blocked_setting(),
            )
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_open_setting_with_incomplete_setting_fail(self):
        """FAIL takes precedence when one setting is open and the other incomplete."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=_all_users_all_apps_allowed(),
                b2b_direct_connect_outbound=CrossTenantB2BSetting(
                    users_and_groups=None, applications=None
                ),
            )
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "B2B collaboration outbound" in result[0].status_extended

    def test_users_allowed_all_but_apps_blocked_pass(self):
        """PASS when users are allowed for all but applications are blocked."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=CrossTenantB2BSetting(
                    users_and_groups=CrossTenantTargetConfiguration(
                        access_type="allowed",
                        targets=[
                            CrossTenantTarget(target="AllUsers", target_type="user")
                        ],
                    ),
                    applications=CrossTenantTargetConfiguration(
                        access_type="blocked",
                        targets=[
                            CrossTenantTarget(
                                target="AllApplications",
                                target_type="application",
                            )
                        ],
                    ),
                ),
                b2b_direct_connect_outbound=_blocked_setting(),
            )
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_apps_allowed_all_but_users_blocked_pass(self):
        """PASS when applications are allowed for all but users are blocked."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=CrossTenantB2BSetting(
                    users_and_groups=CrossTenantTargetConfiguration(
                        access_type="blocked",
                        targets=[
                            CrossTenantTarget(target="AllUsers", target_type="user")
                        ],
                    ),
                    applications=CrossTenantTargetConfiguration(
                        access_type="allowed",
                        targets=[
                            CrossTenantTarget(
                                target="AllApplications",
                                target_type="application",
                            )
                        ],
                    ),
                ),
                b2b_direct_connect_outbound=_blocked_setting(),
            )
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_resource_metadata(self):
        """Verify resource_name and resource_id are set correctly."""
        result = self._run(
            CrossTenantAccessDefault(
                b2b_collaboration_outbound=_blocked_setting(),
                b2b_direct_connect_outbound=_blocked_setting(),
            )
        )
        assert len(result) == 1
        assert result[0].resource_name == "Cross-Tenant Access Default Policy"
        assert result[0].resource_id == "crossTenantAccessPolicyConfigurationDefault"
