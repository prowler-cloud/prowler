import ssl
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest
import requests
from requests import PreparedRequest
from requests.adapters import HTTPAdapter

from prowler.lib.outputs.ocsf import ingestion


@pytest.fixture
def system_trust_session(monkeypatch):
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    native_context = MagicMock()
    ssl_context = MagicMock(return_value=native_context)
    inject_into_ssl = MagicMock()
    monkeypatch.setitem(
        sys.modules,
        "truststore",
        SimpleNamespace(
            SSLContext=ssl_context,
            inject_into_ssl=inject_into_ssl,
        ),
    )

    session = ingestion._SystemTrustSession()
    yield session, native_context, ssl_context, inject_into_ssl
    session.close()


def test_https_origin_pool_uses_native_trust_context(system_trust_session):
    session, native_context, ssl_context, _ = system_trust_session
    adapter = session.get_adapter("https://private.prowler.example")
    request = PreparedRequest()
    request.prepare(method="POST", url="https://private.prowler.example/api/v1")

    _, pool_kwargs = adapter.build_connection_pool_key_attributes(request, verify=True)

    ssl_context.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
    assert pool_kwargs["ssl_context"] is native_context
    assert pool_kwargs["cert_reqs"] == "CERT_REQUIRED"
    assert "ca_certs" not in pool_kwargs
    assert "ca_cert_dir" not in pool_kwargs


def test_native_context_loads_requests_default_ca_bundle(monkeypatch, tmp_path):
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    default_ca_bundle = tmp_path / "requests-default-ca.pem"
    default_ca_bundle.write_text("default CA")
    native_context = MagicMock()
    monkeypatch.setattr(requests.certs, "where", lambda: str(default_ca_bundle))
    monkeypatch.setitem(
        sys.modules,
        "truststore",
        SimpleNamespace(SSLContext=MagicMock(return_value=native_context)),
    )

    session = ingestion._SystemTrustSession()

    native_context.load_verify_locations.assert_called_once_with(
        cafile=str(default_ca_bundle)
    )
    session.close()


def test_native_context_adds_requests_ca_bundle_file(monkeypatch, tmp_path):
    default_ca_bundle = tmp_path / "requests-default-ca.pem"
    configured_ca_bundle = tmp_path / "configured-ca.pem"
    default_ca_bundle.write_text("default CA")
    configured_ca_bundle.write_text("configured CA")
    native_context = MagicMock()
    monkeypatch.setattr(requests.certs, "where", lambda: str(default_ca_bundle))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(configured_ca_bundle))
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    monkeypatch.setitem(
        sys.modules,
        "truststore",
        SimpleNamespace(SSLContext=MagicMock(return_value=native_context)),
    )

    session = ingestion._SystemTrustSession()

    assert native_context.load_verify_locations.call_args_list == [
        call(cafile=str(default_ca_bundle)),
        call(cafile=str(configured_ca_bundle)),
    ]
    session.close()


def test_native_context_uses_curl_ca_bundle_as_fallback(monkeypatch, tmp_path):
    default_ca_bundle = tmp_path / "requests-default-ca.pem"
    configured_ca_bundle = tmp_path / "curl-ca.pem"
    default_ca_bundle.write_text("default CA")
    configured_ca_bundle.write_text("configured CA")
    native_context = MagicMock()
    monkeypatch.setattr(requests.certs, "where", lambda: str(default_ca_bundle))
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.setenv("CURL_CA_BUNDLE", str(configured_ca_bundle))
    monkeypatch.setitem(
        sys.modules,
        "truststore",
        SimpleNamespace(SSLContext=MagicMock(return_value=native_context)),
    )

    session = ingestion._SystemTrustSession()

    assert native_context.load_verify_locations.call_args_list == [
        call(cafile=str(default_ca_bundle)),
        call(cafile=str(configured_ca_bundle)),
    ]
    session.close()


def test_requests_ca_bundle_takes_precedence_over_curl_ca_bundle(monkeypatch, tmp_path):
    default_ca_bundle = tmp_path / "requests-default-ca.pem"
    requests_ca_bundle = tmp_path / "requests-ca.pem"
    curl_ca_bundle = tmp_path / "curl-ca.pem"
    for ca_bundle in (default_ca_bundle, requests_ca_bundle, curl_ca_bundle):
        ca_bundle.write_text("CA")
    native_context = MagicMock()
    monkeypatch.setattr(requests.certs, "where", lambda: str(default_ca_bundle))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(requests_ca_bundle))
    monkeypatch.setenv("CURL_CA_BUNDLE", str(curl_ca_bundle))
    monkeypatch.setitem(
        sys.modules,
        "truststore",
        SimpleNamespace(SSLContext=MagicMock(return_value=native_context)),
    )

    session = ingestion._SystemTrustSession()

    assert native_context.load_verify_locations.call_args_list == [
        call(cafile=str(default_ca_bundle)),
        call(cafile=str(requests_ca_bundle)),
    ]
    session.close()


def test_native_context_adds_configured_ca_directory(monkeypatch, tmp_path):
    default_ca_bundle = tmp_path / "requests-default-ca.pem"
    configured_ca_directory = tmp_path / "configured-ca-directory"
    default_ca_bundle.write_text("default CA")
    configured_ca_directory.mkdir()
    native_context = MagicMock()
    monkeypatch.setattr(requests.certs, "where", lambda: str(default_ca_bundle))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(configured_ca_directory))
    monkeypatch.setitem(
        sys.modules,
        "truststore",
        SimpleNamespace(SSLContext=MagicMock(return_value=native_context)),
    )

    session = ingestion._SystemTrustSession()

    assert native_context.load_verify_locations.call_args_list == [
        call(cafile=str(default_ca_bundle)),
        call(capath=str(configured_ca_directory)),
    ]
    session.close()


@pytest.mark.parametrize("invalid_bundle_source", ["default", "configured"])
def test_invalid_ca_bundle_raises_safe_initialization_error(
    monkeypatch, tmp_path, invalid_bundle_source
):
    default_ca_bundle = tmp_path / "requests-default-ca.pem"
    invalid_ca_bundle = tmp_path / "secret-missing-ca.pem"
    default_ca_bundle.write_text("default CA")
    if invalid_bundle_source == "default":
        monkeypatch.setattr(requests.certs, "where", lambda: str(invalid_ca_bundle))
        monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    else:
        monkeypatch.setattr(requests.certs, "where", lambda: str(default_ca_bundle))
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(invalid_ca_bundle))
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    monkeypatch.setitem(
        sys.modules,
        "truststore",
        SimpleNamespace(SSLContext=MagicMock(return_value=MagicMock())),
    )

    with pytest.raises(
        ingestion.SystemTrustStoreError,
        match="Check the configured CA bundle paths",
    ) as error:
        ingestion._SystemTrustSession()

    assert str(invalid_ca_bundle) not in str(error.value)


def test_session_does_not_inject_global_ssl_or_change_default_adapters(
    system_trust_session,
):
    session, _, _, inject_into_ssl = system_trust_session
    unrelated_session = requests.Session()

    assert type(session.get_adapter("http://private.prowler.example")) is HTTPAdapter
    assert type(unrelated_session.get_adapter("https://example.com")) is HTTPAdapter
    assert type(requests.Session().get_adapter("https://example.com")) is HTTPAdapter
    inject_into_ssl.assert_not_called()

    unrelated_session.close()


def test_environment_proxy_is_preserved_without_replacing_prepared_context(
    monkeypatch, system_trust_session
):
    session, _, _, _ = system_trust_session
    for variable in (
        "ALL_PROXY",
        "CURL_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example:8443")

    settings = session.merge_environment_settings(
        "https://private.prowler.example", {}, None, None, None
    )

    assert settings["verify"] is True
    assert settings["proxies"]["https"] == "https://proxy.example:8443"


def test_https_proxy_uses_native_trust_context(monkeypatch, system_trust_session):
    session, native_context, _, _ = system_trust_session
    adapter = session.get_adapter("https://private.prowler.example")
    proxy_manager = MagicMock()
    proxy_from_url = MagicMock(return_value=proxy_manager)
    monkeypatch.setattr(requests.adapters, "proxy_from_url", proxy_from_url)

    result = adapter.proxy_manager_for("https://proxy.example:8443")

    assert result is proxy_manager
    assert proxy_from_url.call_args.kwargs["proxy_ssl_context"] is native_context


def test_socks_proxy_does_not_receive_proxy_ssl_context(
    monkeypatch, system_trust_session
):
    session, _, _, _ = system_trust_session
    adapter = session.get_adapter("https://private.prowler.example")
    socks_proxy_manager = MagicMock()
    socks_proxy_factory = MagicMock(return_value=socks_proxy_manager)
    monkeypatch.setattr(requests.adapters, "SOCKSProxyManager", socks_proxy_factory)

    result = adapter.proxy_manager_for("socks5h://proxy.example:1080")

    assert result is socks_proxy_manager
    assert "proxy_ssl_context" not in socks_proxy_factory.call_args.kwargs


def test_adapter_keeps_native_verification_without_certifi(system_trust_session):
    session, _, _, _ = system_trust_session
    adapter = session.get_adapter("https://private.prowler.example")
    connection = SimpleNamespace(
        cert_reqs=None,
        ca_certs=None,
        ca_cert_dir=None,
        cert_file=None,
        key_file=None,
    )

    adapter.cert_verify(
        connection,
        "https://private.prowler.example",
        verify=True,
        cert=None,
    )

    assert connection.cert_reqs == "CERT_REQUIRED"
    assert connection.ca_certs is None
    assert connection.ca_cert_dir is None


def test_adapter_rejects_disabled_tls_verification(system_trust_session):
    session, _, _, _ = system_trust_session
    adapter = session.get_adapter("https://private.prowler.example")

    with pytest.raises(ValueError, match="verification is required"):
        adapter.cert_verify(
            MagicMock(),
            "https://private.prowler.example",
            verify=False,
            cert=None,
        )


def test_adapter_does_not_retry_posts(system_trust_session):
    session, _, _, _ = system_trust_session
    adapter = session.get_adapter("https://private.prowler.example")

    assert adapter.max_retries.total == 0


def test_truststore_is_loaded_lazily_and_initialization_errors_are_safe(
    monkeypatch,
):
    assert "truststore" not in ingestion.__dict__
    monkeypatch.setitem(
        sys.modules,
        "truststore",
        SimpleNamespace(SSLContext=MagicMock(side_effect=OSError("secret detail"))),
    )

    with pytest.raises(
        ingestion.SystemTrustStoreError,
        match="Could not initialize the operating system trust store",
    ) as error:
        ingestion._SystemTrustSession()

    assert "secret detail" not in str(error.value)


def test_truststore_import_failure_becomes_custom_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "truststore", None)

    with pytest.raises(ingestion.SystemTrustStoreError):
        ingestion._SystemTrustSession()


def test_upload_preserves_request_and_response_behavior(tmp_path, monkeypatch):
    ocsf_file = tmp_path / "findings.ocsf.json"
    ocsf_file.write_text('{"finding": true}')
    response = MagicMock(status_code=200, text='{"data": {"id": "job-id"}}')
    response.json.return_value = {"data": {"id": "job-id"}}
    session = MagicMock()
    uploaded_file = {}

    def capture_upload(*args, **kwargs):
        filename, file_handle, content_type = kwargs["files"]["file"]
        uploaded_file.update(
            filename=filename,
            content=file_handle.read(),
            content_type=content_type,
        )
        return response

    session.post.side_effect = capture_upload
    monkeypatch.setattr(
        ingestion, "_SystemTrustSession", MagicMock(return_value=session)
    )

    result = ingestion.send_ocsf_to_api(
        str(ocsf_file),
        base_url="private.prowler.example/",
        api_key="safe-api-key",
        timeout=17,
    )

    assert result == {"data": {"id": "job-id"}}
    assert uploaded_file == {
        "filename": "findings.ocsf.json",
        "content": b'{"finding": true}',
        "content_type": "application/json",
    }
    session.post.assert_called_once_with(
        f"https://private.prowler.example{ingestion.cloud_api_ingestion_path}",
        headers={
            "Authorization": "Api-Key safe-api-key",
            "Accept": "application/vnd.api+json",
        },
        files=session.post.call_args.kwargs["files"],
        timeout=17,
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()
    response.json.assert_called_once_with()
    session.close.assert_called_once_with()


@pytest.mark.parametrize(
    "error",
    [requests.exceptions.SSLError("TLS failed"), requests.ConnectionError("offline")],
)
def test_upload_closes_session_when_request_fails(tmp_path, monkeypatch, error):
    ocsf_file = tmp_path / "findings.ocsf.json"
    ocsf_file.write_text("[]")
    session = MagicMock()
    session.post.side_effect = error
    monkeypatch.setattr(
        ingestion, "_SystemTrustSession", MagicMock(return_value=session)
    )

    with pytest.raises(type(error)):
        ingestion.send_ocsf_to_api(
            str(ocsf_file),
            base_url="https://private.prowler.example",
            api_key="safe-api-key",
        )

    session.post.assert_called_once()
    session.close.assert_called_once_with()


def test_empty_response_returns_empty_object_and_closes_session(tmp_path, monkeypatch):
    ocsf_file = tmp_path / "findings.ocsf.json"
    ocsf_file.write_text("[]")
    response = MagicMock(status_code=200, text="")
    session = MagicMock()
    session.post.return_value = response
    monkeypatch.setattr(
        ingestion, "_SystemTrustSession", MagicMock(return_value=session)
    )

    result = ingestion.send_ocsf_to_api(str(ocsf_file), api_key="safe-api-key")

    assert result == {}
    response.json.assert_not_called()
    session.close.assert_called_once_with()


def test_upload_rejects_redirect_response(tmp_path, monkeypatch):
    ocsf_file = tmp_path / "findings.ocsf.json"
    ocsf_file.write_text("[]")
    response = requests.Response()
    response.status_code = 307
    session = MagicMock()
    session.post.return_value = response
    monkeypatch.setattr(
        ingestion, "_SystemTrustSession", MagicMock(return_value=session)
    )

    with pytest.raises(requests.HTTPError, match="redirect") as error:
        ingestion.send_ocsf_to_api(str(ocsf_file), api_key="safe-api-key")

    assert error.value.response is response


@pytest.mark.parametrize("failure_stage", ["status", "json"])
def test_upload_closes_session_when_response_processing_fails(
    tmp_path, monkeypatch, failure_stage
):
    ocsf_file = tmp_path / "findings.ocsf.json"
    ocsf_file.write_text("[]")
    response = MagicMock(status_code=200, text="invalid-json")
    if failure_stage == "status":
        response.raise_for_status.side_effect = requests.HTTPError("forbidden")
    else:
        response.json.side_effect = ValueError("invalid response")
    session = MagicMock()
    session.post.return_value = response
    monkeypatch.setattr(
        ingestion, "_SystemTrustSession", MagicMock(return_value=session)
    )

    with pytest.raises((requests.HTTPError, ValueError)):
        ingestion.send_ocsf_to_api(str(ocsf_file), api_key="safe-api-key")

    session.close.assert_called_once_with()


def test_missing_api_key_fails_before_creating_session(tmp_path, monkeypatch):
    ocsf_file = tmp_path / "findings.ocsf.json"
    ocsf_file.write_text("[]")
    session_factory = MagicMock()
    monkeypatch.setattr(ingestion, "cloud_api_key", None)
    monkeypatch.setattr(ingestion, "_SystemTrustSession", session_factory)

    with pytest.raises(ValueError, match="Missing API key"):
        ingestion.send_ocsf_to_api(str(ocsf_file))

    session_factory.assert_not_called()


def test_missing_file_fails_before_creating_session(tmp_path, monkeypatch):
    session_factory = MagicMock()
    monkeypatch.setattr(ingestion, "_SystemTrustSession", session_factory)

    with pytest.raises(FileNotFoundError, match="OCSF file not found"):
        ingestion.send_ocsf_to_api(
            str(tmp_path / "missing.ocsf.json"), api_key="safe-api-key"
        )

    session_factory.assert_not_called()
