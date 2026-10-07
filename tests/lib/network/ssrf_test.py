import ipaddress
import pathlib
import socket
from unittest import mock

import pytest

from prowler.lib.network.ssrf import (
    ALLOWED_PRIVATE_NETWORKS_ENV,
    SKIP_OUTBOUND_CHECK_ENV,
    OutboundURLNotAllowedError,
    allowed_private_networks,
    extract_host,
    validate_outbound_host,
    validate_outbound_url,
)


def _resolves_to(*addresses):
    return mock.patch.object(
        socket,
        "getaddrinfo",
        return_value=[(2, 1, 6, "", (address, 0)) for address in addresses],
    )


class TestValidateOutboundHost:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "198.18.0.1",
            "203.0.113.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
        ],
    )
    def test_rejects_non_public_literals(self, address):
        with pytest.raises(OutboundURLNotAllowedError):
            validate_outbound_host(address)

    @pytest.mark.parametrize(
        "address", ["100.64.0.1", "100.100.100.200", "100.127.255.254"]
    )
    def test_rejects_shared_address_space(self, address):
        with pytest.raises(OutboundURLNotAllowedError):
            validate_outbound_host(address)

    @pytest.mark.parametrize(
        "address", ["8.8.8.8", "1.1.1.1", "140.82.121.4", "2606:4700:4700::1111"]
    )
    def test_allows_public_literals(self, address):
        validate_outbound_host(address)

    @pytest.mark.parametrize(
        "address",
        ["::ffff:169.254.169.254", "2002:a00:5::", "64:ff9b::a00:5"],
    )
    def test_rejects_ipv6_embedding_a_non_public_ipv4(self, address):
        with pytest.raises(OutboundURLNotAllowedError):
            validate_outbound_host(address)

    def test_rejects_a_hostname_resolving_to_a_private_address(self):
        with _resolves_to("10.0.0.5"):
            with pytest.raises(OutboundURLNotAllowedError):
                validate_outbound_host("registry.internal")

    def test_rejects_a_hostname_with_one_non_public_answer(self):
        with _resolves_to("8.8.8.8", "127.0.0.1"):
            with pytest.raises(OutboundURLNotAllowedError):
                validate_outbound_host("split-horizon.example.com")

    def test_allows_a_hostname_resolving_to_a_public_address(self):
        with _resolves_to("140.82.121.4"):
            validate_outbound_host("github.com")

    def test_rejects_a_hostname_that_does_not_resolve(self):
        with mock.patch.object(
            socket, "getaddrinfo", side_effect=socket.gaierror("no such host")
        ):
            with pytest.raises(OutboundURLNotAllowedError, match="Could not resolve"):
                validate_outbound_host("nowhere.invalid")


class TestOutboundCheckOptOut:
    def test_is_enforced_when_the_variable_is_unset(self, monkeypatch):
        monkeypatch.delenv(SKIP_OUTBOUND_CHECK_ENV, raising=False)
        with pytest.raises(OutboundURLNotAllowedError):
            validate_outbound_host("169.254.169.254")

    @pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on"])
    def test_is_skipped_when_the_variable_is_truthy(self, monkeypatch, raw):
        monkeypatch.setenv(SKIP_OUTBOUND_CHECK_ENV, raw)
        validate_outbound_host("169.254.169.254")

    @pytest.mark.parametrize("raw", ["", "0", "false", "no", "off", "maybe"])
    def test_is_enforced_for_anything_else(self, monkeypatch, raw):
        monkeypatch.setenv(SKIP_OUTBOUND_CHECK_ENV, raw)
        with pytest.raises(OutboundURLNotAllowedError):
            validate_outbound_host("169.254.169.254")

    def test_the_cli_entrypoint_opts_out(self):
        source = pathlib.Path("prowler/__main__.py").read_text()
        assert "os.environ.setdefault(SKIP_OUTBOUND_CHECK_ENV" in source


class TestAllowedPrivateNetworks:
    def test_is_empty_when_unset(self, monkeypatch):
        monkeypatch.delenv(ALLOWED_PRIVATE_NETWORKS_ENV, raising=False)
        assert allowed_private_networks() == ()

    @pytest.mark.parametrize("raw", ["", "   ", ",", " , "])
    def test_is_empty_for_blank_values(self, monkeypatch, raw):
        monkeypatch.setenv(ALLOWED_PRIVATE_NETWORKS_ENV, raw)
        assert allowed_private_networks() == ()

    def test_parses_addresses_and_cidrs(self, monkeypatch):
        monkeypatch.setenv(
            ALLOWED_PRIVATE_NETWORKS_ENV, "10.20.0.0/16, 192.168.65.254 ,fc00::/7"
        )
        assert allowed_private_networks() == (
            ipaddress.ip_network("10.20.0.0/16"),
            ipaddress.ip_network("192.168.65.254/32"),
            ipaddress.ip_network("fc00::/7"),
        )

    def test_rejects_a_malformed_entry(self, monkeypatch):
        monkeypatch.setenv(ALLOWED_PRIVATE_NETWORKS_ENV, "10.20.0.0/16,not-a-network")
        with pytest.raises(OutboundURLNotAllowedError, match="Malformed entry"):
            allowed_private_networks()

    def test_allows_an_address_inside_an_allowlisted_range(self, monkeypatch):
        monkeypatch.setenv(ALLOWED_PRIVATE_NETWORKS_ENV, "10.20.0.0/16")
        validate_outbound_host("10.20.1.5")

    def test_still_rejects_an_address_outside_the_allowlisted_range(self, monkeypatch):
        monkeypatch.setenv(ALLOWED_PRIVATE_NETWORKS_ENV, "10.20.0.0/16")
        with pytest.raises(OutboundURLNotAllowedError):
            validate_outbound_host("169.254.169.254")

    def test_does_not_match_an_allowlist_entry_of_another_family(self, monkeypatch):
        monkeypatch.setenv(ALLOWED_PRIVATE_NETWORKS_ENV, "fc00::/7")
        with pytest.raises(OutboundURLNotAllowedError):
            validate_outbound_host("10.20.1.5")


class TestExtractHost:
    @pytest.mark.parametrize(
        "url, expected",
        [
            ("https://github.com/org/repo", "github.com"),
            (
                "https://user:token@github.com/org/repo",  # trufflehog:ignore
                "github.com",
            ),
            ("https://github.com:8443/org/repo", "github.com"),
            ("git@github.com:org/repo.git", "github.com"),
            ("github.com:org/repo.git", "github.com"),
            ("ssh://git@github.com/org/repo.git", "github.com"),
        ],
    )
    def test_reads_the_host(self, url, expected):
        assert extract_host(url) == expected

    def test_rejects_a_url_without_a_host(self):
        with pytest.raises(OutboundURLNotAllowedError, match="Could not read a host"):
            extract_host("not a url")


class TestValidateOutboundURL:
    def test_rejects_a_disallowed_scheme(self):
        with pytest.raises(OutboundURLNotAllowedError, match="Disallowed URL scheme"):
            validate_outbound_url("file:///etc/passwd")

    def test_allows_an_explicitly_permitted_scheme(self):
        with _resolves_to("140.82.121.4"):
            validate_outbound_url(
                "ssh://git@github.com/org/repo.git",
                allowed_schemes=("http", "https", "ssh", "git"),
            )

    def test_rejects_a_non_public_host_on_an_allowed_scheme(self):
        with pytest.raises(OutboundURLNotAllowedError):
            validate_outbound_url("http://169.254.169.254/latest/meta-data")

    def test_rejects_shared_address_space_on_an_allowed_scheme(self):
        with pytest.raises(OutboundURLNotAllowedError):
            validate_outbound_url("http://100.100.100.200/latest/meta-data")
