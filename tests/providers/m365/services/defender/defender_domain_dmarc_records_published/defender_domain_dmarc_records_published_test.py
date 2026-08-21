from contextlib import contextmanager
from importlib import import_module
from unittest import mock

import dns.resolver

from prowler.providers.m365.services.defender import defender_service
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.defender."
    "defender_domain_dmarc_records_published."
    "defender_domain_dmarc_records_published"
)
GET_PROVIDER = "prowler.providers.common.provider.Provider.get_global_provider"
CONNECT_EXCHANGE = (
    "prowler.providers.m365.lib.powershell.m365_powershell."
    "M365PowerShell.connect_exchange_online"
)
DEFENDER_SERVICE = "prowler.providers.m365.services.defender.defender_service"
DEFENDER_INIT = f"{DEFENDER_SERVICE}.Defender.__init__"


class TXTRecord:
    def __init__(self, *strings):
        self.strings = strings


class Test_defender_domain_dmarc_records_published:
    def test_dmarc_policy_reject(self):
        defender_client = _mock_defender_client("example.com")

        with (
            _mock_m365_provider(),
            _mock_defender_init(),
            mock.patch(
                f"{CHECK_MODULE}.defender_client.defender_client",
                new=defender_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.dns.resolver.resolve",
                return_value=[TXTRecord(b"v=DMARC1; p=reject")],
            ) as resolver_mock,
        ):
            check = _get_check_class()()
            result = check.execute()

            resolver_mock.assert_called_once_with("_dmarc.example.com", "TXT")
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "DMARC record for domain example.com is published with "
                "enforcing policy p=reject."
            )
            config = defender_client.dkim_configurations[0]
            assert result[0].resource == config.dict()
            assert result[0].resource_name == "example.com"
            assert result[0].resource_id == "example.com"
            assert result[0].location == "global"

    def test_dmarc_policy_quarantine_split_txt_chunks(self):
        defender_client = _mock_defender_client("example.org")

        with (
            _mock_m365_provider(),
            _mock_defender_init(),
            mock.patch(
                f"{CHECK_MODULE}.defender_client.defender_client",
                new=defender_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.dns.resolver.resolve",
                return_value=[
                    TXTRecord(b"not-a-dmarc-record"),
                    TXTRecord(b"v=DMARC1; ", b"p=quarantine; pct=100"),
                ],
            ),
        ):
            check = _get_check_class()()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "DMARC record for domain example.org is published with "
                "enforcing policy p=quarantine."
            )

    def test_dmarc_policy_none_fails(self):
        defender_client = _mock_defender_client("example.net")

        with (
            _mock_m365_provider(),
            _mock_defender_init(),
            mock.patch(
                f"{CHECK_MODULE}.defender_client.defender_client",
                new=defender_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.dns.resolver.resolve",
                return_value=[TXTRecord(b"v=DMARC1; p=none")],
            ),
        ):
            check = _get_check_class()()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DMARC record for domain example.net is not published with an "
                "enforcing policy."
            )

    def test_missing_dmarc_record_fails(self):
        defender_client = _mock_defender_client("example.edu")

        with (
            _mock_m365_provider(),
            _mock_defender_init(),
            mock.patch(
                f"{CHECK_MODULE}.defender_client.defender_client",
                new=defender_client,
            ),
            mock.patch(
                f"{CHECK_MODULE}.dns.resolver.resolve",
                side_effect=dns.resolver.NXDOMAIN,
            ),
        ):
            check = _get_check_class()()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DMARC record for domain example.edu is not published with an "
                "enforcing policy."
            )

    def test_no_dkim_configurations(self):
        defender_client = _mock_defender_client()

        with (
            _mock_m365_provider(),
            _mock_defender_init(),
            mock.patch(
                f"{CHECK_MODULE}.defender_client.defender_client",
                new=defender_client,
            ),
        ):
            check = _get_check_class()()
            result = check.execute()

            assert len(result) == 0


def _mock_defender_client(*domains):
    defender_client = mock.MagicMock()
    defender_client.audited_tenant = "audited_tenant"
    defender_client.audited_domain = DOMAIN
    defender_client.dkim_configurations = [
        defender_service.DkimConfig(dkim_signing_enabled=True, id=domain)
        for domain in domains
    ]
    return defender_client


def _mock_m365_provider():
    return mock.patch(
        GET_PROVIDER,
        return_value=set_mocked_m365_provider(),
    )


def _mock_defender_init():
    @contextmanager
    def _patched_defender():
        with (
            mock.patch(CONNECT_EXCHANGE),
            mock.patch(
                DEFENDER_INIT,
                return_value=None,
            ),
        ):
            yield

    return _patched_defender()


def _get_check_class():
    return import_module(CHECK_MODULE).defender_domain_dmarc_records_published
