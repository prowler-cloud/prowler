"""Coverage for the strict scan-config validation and normalization
contract exposed to the Prowler App backend.

Split from :mod:`tests.config.schema.validator_test` because the strict
API (``validate_and_normalize_scan_config``) has different guarantees:
it never silently drops keys, and it returns a JSON-serializable payload
the backend can persist verbatim in a Django ``JSONField``.
"""

import json

import pytest

from prowler.config.scan_config_schema import (
    validate_and_normalize_scan_config,
    validate_scan_config,
)


class Test_Non_Dict_Root:
    @pytest.mark.parametrize("payload", [None, "string", 42, [], (1, 2)])
    def test_non_mapping_root_is_rejected(self, payload):
        normalized, errors = validate_and_normalize_scan_config(payload)
        assert normalized == {}
        assert len(errors) == 1
        assert errors[0]["path"] == "<root>"


class Test_Registered_Provider_Section_Must_Be_Mapping:
    @pytest.mark.parametrize("section", ["a-string", 42, ["s3"], None])
    def test_non_mapping_section_reports_provider_path(self, section):
        normalized, errors = validate_and_normalize_scan_config({"aws": section})
        assert normalized == {}
        assert errors == [{"path": "aws", "message": "section must be a mapping."}]


class Test_Success_Path:
    def test_whitespace_is_normalized_in_exclusions(self):
        normalized, errors = validate_and_normalize_scan_config(
            {
                "aws": {
                    "excluded_checks": [" s3_bucket_public_access "],
                    "excluded_services": [" s3 "],
                }
            }
        )
        assert errors == []
        assert normalized == {
            "aws": {
                "excluded_checks": ["s3_bucket_public_access"],
                "excluded_services": ["s3"],
            }
        }

    def test_plugin_options_are_preserved(self):
        # Third-party plugins inject arbitrary keys inside a provider
        # section; ``extra="allow"`` on the schema keeps them alive
        # through the dump/normalize round-trip.
        normalized, errors = validate_and_normalize_scan_config(
            {"aws": {"plugin_option": "preserved", "another": 42}}
        )
        assert errors == []
        assert normalized == {"aws": {"plugin_option": "preserved", "another": 42}}

    def test_omitted_defaults_are_not_injected(self):
        normalized, errors = validate_and_normalize_scan_config(
            {"aws": {"max_ec2_instance_age_in_days": 90}}
        )
        assert errors == []
        assert normalized == {"aws": {"max_ec2_instance_age_in_days": 90}}
        assert "excluded_checks" not in normalized["aws"]
        assert "excluded_services" not in normalized["aws"]

    def test_unknown_provider_sections_are_preserved_verbatim(self):
        payload = {"future_provider": {"custom_option": True, "nested": {"k": 1}}}
        normalized, errors = validate_and_normalize_scan_config(payload)
        assert errors == []
        assert normalized == payload

    def test_normalized_payload_is_json_serializable(self):
        normalized, _ = validate_and_normalize_scan_config(
            {
                "aws": {
                    "excluded_checks": ["s3_bucket_public_access"],
                    "excluded_services": ["s3"],
                }
            }
        )
        # If ``model_dump(mode="json", ...)`` is ever dropped this
        # ``json.dumps`` call is what will notice.
        json.dumps(normalized)

    def test_input_payload_is_not_mutated(self):
        payload = {
            "aws": {
                "excluded_checks": [" s3_bucket_public_access "],
                "excluded_services": [" s3 "],
            }
        }
        snapshot = json.loads(json.dumps(payload))
        validate_and_normalize_scan_config(payload)
        assert payload == snapshot


class Test_Error_Path:
    def test_invalid_input_returns_empty_normalized_and_errors(self):
        normalized, errors = validate_and_normalize_scan_config(
            {"aws": {"excluded_services": ["s3", " s3 "]}}
        )
        assert normalized == {}
        assert errors
        assert any(err["path"].startswith("aws.excluded_services") for err in errors)

    def test_partial_error_zeros_the_normalized_payload(self):
        # One valid provider + one invalid provider must not leak the
        # valid section into a partially normalized result.
        normalized, errors = validate_and_normalize_scan_config(
            {
                "aws": {"excluded_services": ["s3", "s3"]},
                "azure": {"vm_backup_min_daily_retention_days": 7},
            }
        )
        assert normalized == {}
        assert errors
        assert any(err["path"].startswith("aws.") for err in errors)

    def test_value_error_prefix_is_stripped_from_user_facing_messages(self):
        # Pydantic prefixes messages emitted from ``field_validator``
        # ValueError with ``"Value error, "``. If this test starts to fail
        # because the prefix reappears, either pydantic changed the format
        # or the strip in ``validate_and_normalize_scan_config`` was
        # dropped — either way the UI would render the noisy prefix, so
        # we lock the cleaned message in explicitly.
        _, errors = validate_and_normalize_scan_config(
            {"aws": {"excluded_services": ["s3", "s3"]}}
        )
        assert errors
        message = errors[0]["message"]
        assert not message.startswith("Value error, ")
        assert "duplicate values are not allowed" in message

    def test_all_errors_are_reported_not_only_the_first(self):
        normalized, errors = validate_and_normalize_scan_config(
            {
                "aws": {
                    "excluded_checks": ["", ""],
                    "excluded_services": ["", ""],
                }
            }
        )
        assert normalized == {}
        # ``excluded_checks`` yields per-item empty-string errors AND a
        # duplicate error; ``excluded_services`` yields the same set.
        paths = {err["path"] for err in errors}
        assert any(p.startswith("aws.excluded_checks") for p in paths)
        assert any(p.startswith("aws.excluded_services") for p in paths)


class Test_Non_String_Provider_Keys:
    """The normalized payload is later persisted in a Django JSONField
    keyed by provider. Two entries whose ``str()`` collide (e.g. ``123``
    and ``"123"``) would silently overwrite each other, so non-string
    keys are rejected up front instead of silently coerced."""

    def test_non_string_key_is_rejected(self):
        normalized, errors = validate_and_normalize_scan_config({123: {}})
        assert normalized == {}
        assert errors == [{"path": "123", "message": "provider keys must be strings."}]

    def test_string_and_int_collision_does_not_silently_overwrite(self):
        # If only ``str()`` coercion happened both keys would collapse to
        # ``"aws"`` in the output — this test guards against that regression.
        normalized, errors = validate_and_normalize_scan_config(
            {"aws": {}, 123: {"a": 1}}
        )
        assert normalized == {}
        assert any(err["path"] == "123" for err in errors)


class Test_Unknown_Sections_Must_Be_JSON_Serializable:
    """``normalized`` is persisted by the API in a Django JSONField, so
    unknown provider sections must fail fast here instead of blowing up
    at persist time. Registered sections cannot hit this path — they go
    through ``model_dump(mode="json", ...)`` which already coerces."""

    def test_set_inside_unknown_section_is_rejected(self):
        # ``set`` is a common trap: ``yaml.safe_load`` never produces it,
        # but a hand-built dict might.
        normalized, errors = validate_and_normalize_scan_config(
            {"future_provider": {"values": {1, 2, 3}}}
        )
        assert normalized == {}
        assert errors
        assert errors[0]["path"] == "future_provider"
        assert "JSON-serializable" in errors[0]["message"]

    def test_json_safe_unknown_section_is_still_preserved(self):
        payload = {"future_provider": {"nested": {"k": [1, 2, 3]}}}
        normalized, errors = validate_and_normalize_scan_config(payload)
        assert errors == []
        assert normalized == payload


class Test_Backward_Compatible_Wrapper:
    def test_valid_payload_yields_no_errors(self):
        assert (
            validate_scan_config(
                {"aws": {"excluded_checks": ["s3_bucket_public_access"]}}
            )
            == []
        )

    def test_invalid_payload_yields_only_the_errors(self):
        errors = validate_scan_config({"aws": {"excluded_checks": ["", ""]}})
        assert errors
        assert all(set(err) == {"path", "message"} for err in errors)

    def test_non_mapping_root_matches_new_contract(self):
        assert validate_scan_config(None) == [
            {
                "path": "<root>",
                "message": "Scan config must be a mapping with provider sections.",
            }
        ]
