from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestElbPublicExposure:
    def test_public_load_balancer_fails(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_public_exposure.elb_public_exposure.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_public_exposure.elb_public_exposure import (
                elb_public_exposure,
            )
            from prowler.providers.huaweicloud.services.elb.elb_service import (
                LoadBalancer,
            )

            lb = LoadBalancer(
                id="lb-1",
                name="public-lb",
                is_public=True,
                region="la-south-2",
            )
            elb_client.load_balancers = [lb]
            elb_client.audited_account = "123456789012"

            check = elb_public_exposure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "public" in result[0].status_extended

    def test_internal_load_balancer_passes(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_public_exposure.elb_public_exposure.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_public_exposure.elb_public_exposure import (
                elb_public_exposure,
            )
            from prowler.providers.huaweicloud.services.elb.elb_service import (
                LoadBalancer,
            )

            lb = LoadBalancer(
                id="lb-1",
                name="internal-lb",
                is_public=False,
                region="la-south-2",
            )
            elb_client.load_balancers = [lb]
            elb_client.audited_account = "123456789012"

            check = elb_public_exposure()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_no_load_balancers(self):
        elb_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.elb.elb_public_exposure.elb_public_exposure.elb_client",
                new=elb_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.elb.elb_public_exposure.elb_public_exposure import (
                elb_public_exposure,
            )

            elb_client.load_balancers = []
            elb_client.audited_account = "123456789012"

            check = elb_public_exposure()
            result = check.execute()

            assert len(result) == 0
