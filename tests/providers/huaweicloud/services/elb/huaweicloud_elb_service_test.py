from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.elb.elb_service import ELB, LoadBalancer
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _provider_with_client(regional_client):
    """Return a mocked provider whose regional client is the given mock."""
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.generate_regional_clients = mock.MagicMock(
        return_value={REGION: regional_client}
    )
    return provider


class TestELBService:
    def test_list_load_balancers_public_via_publicips(self):
        lb_data = SimpleNamespace(
            id="lb-1",
            name="public-lb",
            vip_address="10.0.0.5",
            publicips=[SimpleNamespace(publicip_address="1.2.3.4")],
            eips=None,
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_load_balancers.return_value = SimpleNamespace(
            loadbalancers=[lb_data]
        )

        elb = ELB(_provider_with_client(regional_client))

        assert len(elb.load_balancers) == 1
        lb = elb.load_balancers[0]
        assert isinstance(lb, LoadBalancer)
        assert lb.id == "lb-1"
        assert lb.name == "public-lb"
        assert lb.vip_address == "10.0.0.5"
        assert lb.public_ip == "1.2.3.4"
        assert lb.is_public is True
        assert lb.region == REGION

    def test_list_load_balancers_public_via_eips(self):
        lb_data = SimpleNamespace(
            id="lb-2",
            name="eip-lb",
            vip_address="10.0.0.6",
            publicips=None,
            eips=[SimpleNamespace(eip_address="5.6.7.8")],
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_load_balancers.return_value = SimpleNamespace(
            loadbalancers=[lb_data]
        )

        elb = ELB(_provider_with_client(regional_client))

        lb = elb.load_balancers[0]
        assert lb.public_ip == "5.6.7.8"
        assert lb.is_public is True

    def test_list_load_balancers_private(self):
        lb_data = SimpleNamespace(
            id="lb-3",
            name="private-lb",
            vip_address="10.0.0.7",
            publicips=None,
            eips=None,
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_load_balancers.return_value = SimpleNamespace(
            loadbalancers=[lb_data]
        )

        elb = ELB(_provider_with_client(regional_client))

        lb = elb.load_balancers[0]
        assert lb.public_ip == ""
        assert lb.is_public is False

    def test_list_load_balancers_empty(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_load_balancers.return_value = SimpleNamespace(
            loadbalancers=[]
        )

        elb = ELB(_provider_with_client(regional_client))

        assert elb.load_balancers == []

    def test_list_load_balancers_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_load_balancers.side_effect = Exception("boom")

        elb = ELB(_provider_with_client(regional_client))

        # Errors are logged and swallowed; no partial/garbage resources.
        assert elb.load_balancers == []

    def test_list_listeners_parses_listeners(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_load_balancers.return_value = SimpleNamespace(
            loadbalancers=[]
        )
        regional_client.list_listeners.return_value = SimpleNamespace(
            listeners=[
                SimpleNamespace(
                    id="lis-1",
                    name="https-lis",
                    protocol="HTTPS",
                    protocol_port=443,
                    tls_ciphers_policy="tls-1-2-strict",
                    security_policy_id="sp-1",
                )
            ],
            page_info=SimpleNamespace(next_marker=None),
        )
        regional_client.show_security_policy.return_value = SimpleNamespace(
            security_policy=SimpleNamespace(protocols=["TLSv1.2", "TLSv1.3"])
        )

        elb = ELB(_provider_with_client(regional_client))

        assert len(elb.listeners) == 1
        lis = elb.listeners[0]
        assert lis.id == "lis-1"
        assert lis.name == "https-lis"
        assert lis.protocol == "HTTPS"
        assert lis.protocol_port == 443
        assert lis.tls_ciphers_policy == "tls-1-2-strict"
        assert lis.security_policy_id == "sp-1"
        assert lis.security_policy_protocols == ["TLSv1.2", "TLSv1.3"]
        assert lis.region == REGION

    def test_list_listeners_paginates(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_load_balancers.return_value = SimpleNamespace(
            loadbalancers=[]
        )
        page1 = [
            SimpleNamespace(
                id=f"lis-{i}",
                name=f"lis-{i}",
                protocol="HTTPS",
                protocol_port=443,
                tls_ciphers_policy="tls-1-2-strict",
                security_policy_id="",
            )
            for i in range(2000)
        ]
        page2 = [
            SimpleNamespace(
                id="lis-2000",
                name="lis-2000",
                protocol="HTTPS",
                protocol_port=443,
                tls_ciphers_policy="tls-1-3",
                security_policy_id="",
            )
        ]
        regional_client.list_listeners.side_effect = [
            SimpleNamespace(
                listeners=page1,
                page_info=SimpleNamespace(next_marker="lis-1999"),
            ),
            SimpleNamespace(
                listeners=page2,
                page_info=SimpleNamespace(next_marker=None),
            ),
        ]

        elb = ELB(_provider_with_client(regional_client))

        assert len(elb.listeners) == 2001
        assert elb.listeners[-1].id == "lis-2000"
        assert regional_client.list_listeners.call_count == 2
        assert (
            regional_client.list_listeners.call_args_list[1].args[0].marker
            == "lis-1999"
        )

    def test_list_listeners_security_policy_error_sets_none(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_load_balancers.return_value = SimpleNamespace(
            loadbalancers=[]
        )
        regional_client.list_listeners.return_value = SimpleNamespace(
            listeners=[
                SimpleNamespace(
                    id="lis-err",
                    name="custom-lis",
                    protocol="HTTPS",
                    protocol_port=443,
                    tls_ciphers_policy="tls-1-2-strict",
                    security_policy_id="sp-missing",
                )
            ],
            page_info=SimpleNamespace(next_marker=None),
        )
        regional_client.show_security_policy.side_effect = Exception("boom")

        elb = ELB(_provider_with_client(regional_client))

        assert len(elb.listeners) == 1
        assert elb.listeners[0].security_policy_id == "sp-missing"
        assert elb.listeners[0].security_policy_protocols is None
