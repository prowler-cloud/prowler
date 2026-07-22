"""Coverage for the ``excluded_checks`` / ``excluded_services`` fields
added to :class:`prowler.config.schema.base.ProviderConfigBase`.

Because the fields live on the base class, every registered provider
schema exposes them and every provider must therefore share the same
whitespace / uniqueness / non-empty guarantees. These tests lock in that
contract at the base level and at the JSON-Schema level (which the UI
editor consumes via ``ajv``).
"""

import pytest
from pydantic import ValidationError

from prowler.config.scan_config_schema import SCAN_CONFIG_SCHEMA
from prowler.config.schema.aws import AWSProviderConfig
from prowler.config.schema.registry import SCHEMAS
from prowler.config.schema.validator import validate_provider_config
from prowler.providers.common.provider import Provider

EXCLUSION_FIELDS = ("excluded_checks", "excluded_services")


class Test_JSON_Schema_Exposes_Exclusion_Fields:
    # The aggregated schema is app-facing and only carries app providers
    # (``sdk_only = False``); iterate exactly what it exposes so SDK/CLI-only
    # providers (still in ``SCHEMAS`` for CLI validation) are not asserted here.
    @pytest.mark.parametrize(
        "provider", sorted(set(Provider.get_app_providers()) & set(SCHEMAS))
    )
    @pytest.mark.parametrize("field", EXCLUSION_FIELDS)
    def test_field_shape(self, provider, field):
        field_schema = SCAN_CONFIG_SCHEMA["properties"][provider]["properties"][field]
        assert field_schema["type"] == "array"
        assert field_schema["items"] == {"type": "string", "minLength": 1}
        assert field_schema["uniqueItems"] is True
        assert field_schema["default"] == []


class Test_Exclusion_Field_Validation:
    def _model(self, **kwargs):
        return AWSProviderConfig.model_validate(kwargs)

    @pytest.mark.parametrize("field", EXCLUSION_FIELDS)
    def test_empty_string_is_rejected(self, field):
        with pytest.raises(ValidationError):
            self._model(**{field: [""]})

    @pytest.mark.parametrize("field", EXCLUSION_FIELDS)
    def test_whitespace_only_string_is_rejected(self, field):
        with pytest.raises(ValidationError):
            self._model(**{field: ["   "]})

    @pytest.mark.parametrize("field", EXCLUSION_FIELDS)
    def test_raw_duplicates_are_rejected(self, field):
        with pytest.raises(ValidationError):
            self._model(**{field: ["s3", "s3"]})

    @pytest.mark.parametrize("field", EXCLUSION_FIELDS)
    def test_normalized_duplicates_are_rejected(self, field):
        # After whitespace normalization ``" s3 "`` collapses to ``"s3"``
        # and must be caught by the duplicate check.
        with pytest.raises(ValidationError):
            self._model(**{field: ["s3", " s3 "]})

    @pytest.mark.parametrize("field", EXCLUSION_FIELDS)
    def test_whitespace_is_stripped(self, field):
        model = self._model(**{field: [" identifier "]})
        assert getattr(model, field) == ["identifier"]

    @pytest.mark.parametrize("field", EXCLUSION_FIELDS)
    def test_non_string_item_is_rejected(self, field):
        with pytest.raises(ValidationError):
            self._model(**{field: [123]})


class Test_Exclusion_Defaults_Are_Not_Injected:
    """The strict normalization path uses ``model_dump(exclude_unset=True)``
    so pre-existing configs that never set an exclusion field must round-trip
    without the default empty list being materialized."""

    def test_absent_fields_are_not_injected_by_validator(self):
        # The lenient SDK runtime path also uses ``exclude_unset=True`` under
        # the hood; asserting on the validator output guards the promise
        # against future refactors.
        assert validate_provider_config("aws", {}, SCHEMAS["aws"]) == {}

    def test_absent_fields_are_not_injected_when_other_keys_are_present(self):
        assert validate_provider_config(
            "aws",
            {"max_ec2_instance_age_in_days": 180},
            SCHEMAS["aws"],
        ) == {"max_ec2_instance_age_in_days": 180}

    def test_explicit_empty_list_round_trips(self):
        # Explicitly setting ``excluded_checks: []`` is different from
        # omitting it — the empty list is user-provided and must be
        # preserved by the strict-normalization contract.
        assert validate_provider_config(
            "aws",
            {"excluded_checks": []},
            SCHEMAS["aws"],
        ) == {"excluded_checks": []}


class Test_Extra_Fields_Are_Preserved:
    """``extra="allow"`` must keep plugin-provided keys around so the
    ecosystem contract in ``validator_test.py`` still holds after adding
    the exclusion fields."""

    def test_unknown_keys_are_preserved_alongside_exclusions(self):
        out = validate_provider_config(
            "aws",
            {"excluded_checks": ["s3_bucket_public_access"], "plugin_option": "kept"},
            SCHEMAS["aws"],
        )
        assert out == {
            "excluded_checks": ["s3_bucket_public_access"],
            "plugin_option": "kept",
        }
