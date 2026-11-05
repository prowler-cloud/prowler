from unittest.mock import MagicMock

import pytest
import requests

from prowler import __main__ as cli
from prowler.lib.outputs.ocsf.ingestion import SystemTrustStoreError


def test_ssl_error_uses_actionable_tls_message_before_connection_error(
    monkeypatch, capsys
):
    upload = MagicMock(
        side_effect=requests.exceptions.SSLError("secret transport detail")
    )
    monkeypatch.setattr(cli, "send_ocsf_to_api", upload)

    response = cli._send_ocsf_to_cloud("/tmp/saved-findings.ocsf.json")

    output = capsys.readouterr().out
    assert response is None
    assert "TLS certificate validation failed" in output
    assert "hostname, validity period, and certificate chain" in output
    assert "operating system trust store" in output
    assert "TLS-intercepting proxy CA" in output
    assert "container system CA store" in output
    assert "Scan results were saved to /tmp/saved-findings.ocsf.json" in output
    assert "secret transport detail" not in output


def test_truststore_initialization_error_uses_safe_actionable_message(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        cli,
        "send_ocsf_to_api",
        MagicMock(side_effect=SystemTrustStoreError("secret initialization detail")),
    )

    response = cli._send_ocsf_to_cloud("/tmp/saved-findings.ocsf.json")

    output = capsys.readouterr().out
    assert response is None
    assert "operating system trust store could not be initialized" in output
    assert "configured CA bundle paths" in output
    assert "TLS-intercepting proxy CA" in output
    assert "container system CA store" in output
    assert "Scan results were saved to /tmp/saved-findings.ocsf.json" in output
    assert "secret initialization detail" not in output


def test_json_decode_error_uses_safe_api_response_message(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "send_ocsf_to_api",
        MagicMock(
            side_effect=requests.exceptions.JSONDecodeError(
                "secret response detail", "invalid", 0
            )
        ),
    )

    response = cli._send_ocsf_to_cloud("/tmp/saved-findings.ocsf.json")

    output = capsys.readouterr().out
    assert response is None
    assert "the API returned an invalid JSON response" in output
    assert "no API key configured" not in output
    assert "secret response detail" not in output
    assert "Scan results were saved to /tmp/saved-findings.ocsf.json" in output


def test_http_error_without_response_uses_safe_fallback(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "send_ocsf_to_api",
        MagicMock(side_effect=requests.HTTPError("secret transport detail")),
    )

    response = cli._send_ocsf_to_cloud("/tmp/saved-findings.ocsf.json")

    output = capsys.readouterr().out
    assert response is None
    assert "the API request failed without a response status" in output
    assert "secret transport detail" not in output
    assert "Scan results were saved to /tmp/saved-findings.ocsf.json" in output


@pytest.mark.parametrize(
    ("error", "expected_message"),
    [
        (
            ValueError("missing"),
            "Push to Prowler Cloud skipped: no API key configured",
        ),
        (
            requests.ConnectionError("offline"),
            "could not reach the Prowler Cloud API",
        ),
        (
            requests.HTTPError(response=MagicMock(status_code=402)),
            "only available with a Prowler Cloud subscription",
        ),
        (
            requests.HTTPError(response=MagicMock(status_code=403)),
            "the API returned HTTP 403",
        ),
    ],
)
def test_existing_upload_errors_keep_specific_messages(
    monkeypatch, capsys, error, expected_message
):
    monkeypatch.setattr(cli, "send_ocsf_to_api", MagicMock(side_effect=error))

    response = cli._send_ocsf_to_cloud("/tmp/saved-findings.ocsf.json")

    output = capsys.readouterr().out
    assert response is None
    assert expected_message in output
    assert "Scan results were saved to /tmp/saved-findings.ocsf.json" in output


def test_successful_upload_returns_response(monkeypatch, capsys):
    expected_response = {"data": {"id": "job-id"}}
    monkeypatch.setattr(
        cli, "send_ocsf_to_api", MagicMock(return_value=expected_response)
    )

    response = cli._send_ocsf_to_cloud("/tmp/saved-findings.ocsf.json")

    assert response == expected_response
    assert capsys.readouterr().out == ""
