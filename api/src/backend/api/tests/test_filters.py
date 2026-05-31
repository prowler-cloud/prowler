from api.filters import get_provider_type_choices
from prowler.providers.common.provider import Provider as SDKProvider


class TestProviderTypeChoices:
    """Provider-type filter choices are driven by the SDK's available providers
    so filtering covers external providers, not just a static enum."""

    def test_choices_track_sdk_available_providers(self):
        available = set(SDKProvider.get_available_providers())
        choices = get_provider_type_choices()

        assert {value for value, _ in choices} == available

    def test_choices_include_provider_absent_from_legacy_enum(self):
        from api.models import Provider

        legacy = {value for value, _ in Provider.ProviderChoices.choices}
        choice_values = {value for value, _ in get_provider_type_choices()}

        # `llm` is exposed by the SDK but is not part of the legacy static enum.
        assert "llm" in choice_values
        assert "llm" not in legacy
