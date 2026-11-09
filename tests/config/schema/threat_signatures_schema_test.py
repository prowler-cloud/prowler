"""``threat_signatures`` in scan configurations: how a tenant sends an emerging threat."""

import json

import pytest

from prowler.config.scan_config_schema import (
    SCAN_CONFIG_SCHEMA,
    validate_and_normalize_scan_config,
)
from prowler.lib.threats import load_signatures
from tests.lib.threats.demo_signature import DEMO_SSH_BYPASS


def tenant_signature(**overrides) -> dict:
    signature = dict(DEMO_SSH_BYPASS)
    signature.update({"id": "tenant-threat", **overrides})
    return signature


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_valid_signature_is_normalized_and_loadable(provider):
    normalized, errors = validate_and_normalize_scan_config(
        {provider: {"threat_signatures": [tenant_signature()]}}
    )
    assert errors == []
    json.dumps(normalized)  # persisted verbatim in a JSONField
    loaded = {s.id for s in load_signatures(normalized[provider])}
    assert "tenant-threat" in loaded


def test_invalid_signature_is_rejected_with_a_path():
    _, errors = validate_and_normalize_scan_config(
        {"aws": {"threat_signatures": [tenant_signature(id="Not A Slug")]}}
    )
    assert errors and errors[0]["path"] == "aws.threat_signatures[0].id"


def test_duplicate_ids_are_rejected():
    _, errors = validate_and_normalize_scan_config(
        {"gcp": {"threat_signatures": [tenant_signature(), tenant_signature()]}}
    )
    assert errors and "duplicate threat signature ids" in errors[0]["message"]


def test_schema_documents_the_key_for_the_ui_editor():
    assert "threat_signatures" in json.dumps(SCAN_CONFIG_SCHEMA)


def test_scan_time_loading_drops_only_the_invalid_signature(caplog):
    # Scans (the CLI config file, and Prowler Cloud with its catalog merged in)
    # load leniently: one bad entry must not take the others with it.
    from prowler.config.schema.aws import AWSProviderConfig
    from prowler.config.schema.validator import validate_provider_config

    raw = {
        "max_security_group_rules": 40,
        "threat_signatures": [
            tenant_signature(id="Not A Slug"),
            tenant_signature(id="kept-threat"),
        ],
    }

    config = validate_provider_config("aws", raw, AWSProviderConfig)

    assert config["max_security_group_rules"] == 40
    assert [s["id"] for s in config["threat_signatures"]] == ["kept-threat"]
    assert "threat_signatures" in caplog.text
