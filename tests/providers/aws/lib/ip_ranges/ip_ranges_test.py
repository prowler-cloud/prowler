import json
from ipaddress import IPv4Network, IPv6Network, ip_address
from unittest.mock import MagicMock, patch

from prowler.providers.aws.lib.ip_ranges.ip_ranges import get_public_ip_networks

SAMPLE_RANGES = {
    "prefixes": [
        {"ip_prefix": "54.152.0.0/16", "service": "AMAZON"},
        {"ip_prefix": "3.5.140.0/22", "service": "S3"},
    ],
    "ipv6_prefixes": [
        {"ipv6_prefix": "2600:1f00::/24", "service": "AMAZON"},
    ],
}


def mock_urlopen(payload):
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode()
    context_manager = MagicMock()
    context_manager.__enter__.return_value = response
    context_manager.__exit__.return_value = False
    return context_manager


class TestGetPublicIPNetworks:
    def test_parses_ipv4_and_ipv6_prefixes(self):
        with patch(
            "prowler.providers.aws.lib.ip_ranges.ip_ranges.urllib.request.urlopen",
            return_value=mock_urlopen(SAMPLE_RANGES),
        ):
            networks = get_public_ip_networks()

        assert networks == [
            IPv4Network("54.152.0.0/16"),
            IPv4Network("3.5.140.0/22"),
            IPv6Network("2600:1f00::/24"),
        ]

    def test_known_aws_ip_is_contained(self):
        with patch(
            "prowler.providers.aws.lib.ip_ranges.ip_ranges.urllib.request.urlopen",
            return_value=mock_urlopen(SAMPLE_RANGES),
        ):
            networks = get_public_ip_networks()

        assert any(ip_address("54.152.12.70") in network for network in networks)

    def test_external_ip_is_not_contained(self):
        with patch(
            "prowler.providers.aws.lib.ip_ranges.ip_ranges.urllib.request.urlopen",
            return_value=mock_urlopen(SAMPLE_RANGES),
        ):
            networks = get_public_ip_networks()

        assert not any(ip_address("17.5.7.3") in network for network in networks)

    def test_empty_payload_returns_empty_list(self):
        with patch(
            "prowler.providers.aws.lib.ip_ranges.ip_ranges.urllib.request.urlopen",
            return_value=mock_urlopen({}),
        ):
            networks = get_public_ip_networks()

        assert networks == []

    def test_prefixes_missing_cidr_are_skipped(self):
        payload = {
            "prefixes": [{"ip_prefix": "10.0.0.0/8"}, {"service": "EC2"}],
            "ipv6_prefixes": [{"service": "AMAZON"}],
        }
        with patch(
            "prowler.providers.aws.lib.ip_ranges.ip_ranges.urllib.request.urlopen",
            return_value=mock_urlopen(payload),
        ):
            networks = get_public_ip_networks()

        assert networks == [IPv4Network("10.0.0.0/8")]
