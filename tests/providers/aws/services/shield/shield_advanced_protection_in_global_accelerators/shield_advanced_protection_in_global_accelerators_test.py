from unittest import mock

from prowler.providers.aws.services.globalaccelerator.globalaccelerator_service import (
    Accelerator,
)
from prowler.providers.aws.services.shield.shield_service import Protection
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class Test_shield_advanced_protection_in_global_accelerators:
    def test_no_shield_not_active(self):
        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        # GlobalAccelerator Client
        globalaccelerator_client = mock.MagicMock
        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.services.globalaccelerator.globalaccelerator_service.GlobalAccelerator",
            new=globalaccelerator_client,
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_global_accelerators.shield_advanced_protection_in_global_accelerators import (
                shield_advanced_protection_in_global_accelerators,
            )

            check = shield_advanced_protection_in_global_accelerators()
            result = check.execute()

            assert len(result) == 0

    def test_shield_enabled_globalaccelerator_protected(self):
        # GlobalAccelerator Client
        globalaccelerator_client = mock.MagicMock
        accelerator_name = "1234abcd-abcd-1234-abcd-1234abcdefgh"
        accelerator_id = "1234abcd-abcd-1234-abcd-1234abcdefgh"
        accelerator_arn = f"arn:aws:globalaccelerator::{AWS_ACCOUNT_NUMBER}:accelerator/{accelerator_id}"
        globalaccelerator_client.accelerators = {
            accelerator_name: Accelerator(
                arn=accelerator_arn,
                name=accelerator_name,
                region=AWS_REGION_EU_WEST_1,
                enabled=True,
            )
        }

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION_EU_WEST_1
        protection_id = "test-protection"
        shield_client.protections = {
            protection_id: Protection(
                id=protection_id,
                name="",
                resource_arn=accelerator_arn,
                protection_arn="",
                region=AWS_REGION_EU_WEST_1,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.services.globalaccelerator.globalaccelerator_service.GlobalAccelerator",
            new=globalaccelerator_client,
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_global_accelerators.shield_advanced_protection_in_global_accelerators import (
                shield_advanced_protection_in_global_accelerators,
            )

            check = shield_advanced_protection_in_global_accelerators()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == accelerator_id
            assert result[0].resource_arn == accelerator_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Global Accelerator {accelerator_id} is protected by AWS Shield Advanced."
            )

    def test_shield_enabled_globalaccelerator_not_protected(self):
        # GlobalAccelerator Client
        globalaccelerator_client = mock.MagicMock
        accelerator_name = "1234abcd-abcd-1234-abcd-1234abcdefgh"
        accelerator_id = "1234abcd-abcd-1234-abcd-1234abcdefgh"
        accelerator_arn = f"arn:aws:globalaccelerator::{AWS_ACCOUNT_NUMBER}:accelerator/{accelerator_id}"
        globalaccelerator_client.accelerators = {
            accelerator_name: Accelerator(
                arn=accelerator_arn,
                name=accelerator_name,
                region=AWS_REGION_EU_WEST_1,
                enabled=True,
            )
        }

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION_EU_WEST_1
        shield_client.protections = {}

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.services.globalaccelerator.globalaccelerator_service.GlobalAccelerator",
            new=globalaccelerator_client,
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_global_accelerators.shield_advanced_protection_in_global_accelerators import (
                shield_advanced_protection_in_global_accelerators,
            )

            check = shield_advanced_protection_in_global_accelerators()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == accelerator_id
            assert result[0].resource_arn == accelerator_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Global Accelerator {accelerator_id} is not protected by AWS Shield Advanced."
            )

    def test_shield_disabled_globalaccelerator_not_protected(self):
        # GlobalAccelerator Client
        globalaccelerator_client = mock.MagicMock
        accelerator_name = "1234abcd-abcd-1234-abcd-1234abcdefgh"
        accelerator_id = "1234abcd-abcd-1234-abcd-1234abcdefgh"
        accelerator_arn = f"arn:aws:globalaccelerator::{AWS_ACCOUNT_NUMBER}:accelerator/{accelerator_id}"
        globalaccelerator_client.accelerators = {
            accelerator_name: Accelerator(
                arn=accelerator_arn,
                name=accelerator_name,
                region=AWS_REGION_EU_WEST_1,
                enabled=True,
            )
        }

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        shield_client.region = AWS_REGION_EU_WEST_1
        shield_client.protections = {}

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.services.globalaccelerator.globalaccelerator_service.GlobalAccelerator",
            new=globalaccelerator_client,
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_global_accelerators.shield_advanced_protection_in_global_accelerators import (
                shield_advanced_protection_in_global_accelerators,
            )

            check = shield_advanced_protection_in_global_accelerators()
            result = check.execute()

            assert len(result) == 0
