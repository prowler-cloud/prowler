from api.filters import get_provider_type_choices
from prowler.providers.common.provider import Provider as SDKProvider


class TestProviderTypeChoices:
    """Provider-type filter choices are driven by the SDK's app-facing providers
    (``sdk_only = False``) so filtering covers external providers that opt in,
    while hiding providers the API does not expose (``sdk_only = True``)."""

    def test_choices_track_sdk_app_providers(self):
        app_providers = set(SDKProvider.get_app_providers())
        choices = get_provider_type_choices()

        assert {value for value, _ in choices} == app_providers

    def test_choices_exclude_sdk_only_providers(self):
        choice_values = {value for value, _ in get_provider_type_choices()}

        # These built-ins are not implemented in the API, so they keep the
        # default ``sdk_only = True`` and must not appear as filter choices,
        # even though the SDK still lists them in get_available_providers().
        available = set(SDKProvider.get_available_providers())
        for sdk_only_provider in ("llm", "nhn", "scaleway", "stackit"):
            assert sdk_only_provider in available
            assert sdk_only_provider not in choice_values

    def test_choices_include_app_exposed_builtins(self):
        choice_values = {value for value, _ in get_provider_type_choices()}

        assert "aws" in choice_values
        assert "azure" in choice_values
