from unittest import mock

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1

# Patching the fixer client imports securityhub_client, which instantiates
# SecurityHub against the global provider at module level. Stubbing the class
# first keeps that import from reaching AWS when this file runs on its own.
SERVICE_MODULE = "prowler.providers.aws.services.securityhub.securityhub_service"
FIXER_MODULE = "prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled_fixer"


def _mocked_securityhub_client(fixer_config: dict) -> tuple:
    """Build a Security Hub client mock with a single regional client."""
    regional_client = mock.MagicMock()
    securityhub_client = mock.MagicMock()
    securityhub_client.fixer_config = fixer_config
    securityhub_client.regional_clients = {AWS_REGION_EU_WEST_1: regional_client}
    return securityhub_client, regional_client


class Test_securityhub_enabled_fixer:
    def test_securityhub_enabled_fixer(self):
        """Security Hub is enabled with the default standards from the fixer config."""
        securityhub_client, regional_client = _mocked_securityhub_client(
            {"securityhub_enabled": {"EnableDefaultStandards": True}}
        )

        with (
            mock.patch(f"{SERVICE_MODULE}.SecurityHub", new=mock.MagicMock()),
            mock.patch(f"{FIXER_MODULE}.securityhub_client", new=securityhub_client),
        ):
            # Test Fixer
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled_fixer import (
                fixer,
            )

            assert fixer(AWS_REGION_EU_WEST_1)

        regional_client.enable_security_hub.assert_called_once_with(
            EnableDefaultStandards=True
        )

    def test_securityhub_enabled_fixer_default_standards_disabled(self):
        """EnableDefaultStandards must be taken from the fixer configuration."""
        securityhub_client, regional_client = _mocked_securityhub_client(
            {"securityhub_enabled": {"EnableDefaultStandards": False}}
        )

        with (
            mock.patch(f"{SERVICE_MODULE}.SecurityHub", new=mock.MagicMock()),
            mock.patch(f"{FIXER_MODULE}.securityhub_client", new=securityhub_client),
        ):
            # Test Fixer
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled_fixer import (
                fixer,
            )

            assert fixer(AWS_REGION_EU_WEST_1)

        regional_client.enable_security_hub.assert_called_once_with(
            EnableDefaultStandards=False
        )

    def test_securityhub_enabled_fixer_error(self):
        """A failing EnableSecurityHub call must return False instead of raising."""
        securityhub_client, regional_client = _mocked_securityhub_client({})
        regional_client.enable_security_hub.side_effect = Exception(
            "AccessDeniedException"
        )

        with (
            mock.patch(f"{SERVICE_MODULE}.SecurityHub", new=mock.MagicMock()),
            mock.patch(f"{FIXER_MODULE}.securityhub_client", new=securityhub_client),
        ):
            # Test Fixer
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled_fixer import (
                fixer,
            )

            assert not fixer(AWS_REGION_EU_WEST_1)
