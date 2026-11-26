from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_cbr_policy_retention:
    def test_cbr_policy_retention_pass(self):
        cbr_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention.cbr_client",
                new=cbr_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cbr.cbr_service import (
                CBRPolicy,
            )
            from prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention import (
                cbr_policy_retention,
            )

            cbr_client.policies = [
                CBRPolicy(
                    policy_id="cbr-policy-001",
                    name="policy-good-retention",
                    retention_duration_days=30,
                    region="la-south-2",
                ),
            ]
            cbr_client.audited_account = "123456789012"

            check = cbr_policy_retention()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert results[0].resource_id == "cbr-policy-001"
            assert "30 day(s)" in results[0].status_extended

    def test_cbr_policy_retention_fail(self):
        cbr_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention.cbr_client",
                new=cbr_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cbr.cbr_service import (
                CBRPolicy,
            )
            from prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention import (
                cbr_policy_retention,
            )

            cbr_client.policies = [
                CBRPolicy(
                    policy_id="cbr-policy-002",
                    name="policy-short-retention",
                    retention_duration_days=3,
                    region="la-south-2",
                ),
            ]
            cbr_client.audited_account = "123456789012"

            check = cbr_policy_retention()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "cbr-policy-002"
            assert "3 day(s)" in results[0].status_extended

    def test_cbr_policy_retention_boundary(self):
        cbr_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention.cbr_client",
                new=cbr_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cbr.cbr_service import (
                CBRPolicy,
            )
            from prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention import (
                cbr_policy_retention,
            )

            cbr_client.policies = [
                CBRPolicy(
                    policy_id="cbr-policy-003",
                    name="policy-exact-7-days",
                    retention_duration_days=7,
                    region="la-south-2",
                ),
            ]
            cbr_client.audited_account = "123456789012"

            check = cbr_policy_retention()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert "7 day(s)" in results[0].status_extended

    def test_cbr_policy_retention_mixed(self):
        cbr_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention.cbr_client",
                new=cbr_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cbr.cbr_service import (
                CBRPolicy,
            )
            from prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention import (
                cbr_policy_retention,
            )

            cbr_client.policies = [
                CBRPolicy(
                    policy_id="cbr-policy-001",
                    name="policy-good-retention",
                    retention_duration_days=30,
                    region="la-south-2",
                ),
                CBRPolicy(
                    policy_id="cbr-policy-002",
                    name="policy-short-retention",
                    retention_duration_days=3,
                    region="la-south-2",
                ),
            ]
            cbr_client.audited_account = "123456789012"

            check = cbr_policy_retention()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "PASS"
            assert results[1].status == "FAIL"

    def test_cbr_policy_retention_empty(self):
        cbr_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention.cbr_client",
                new=cbr_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cbr.cbr_policy_retention.cbr_policy_retention import (
                cbr_policy_retention,
            )

            cbr_client.policies = []
            cbr_client.audited_account = "123456789012"

            check = cbr_policy_retention()
            results = check.execute()

            assert len(results) == 0
