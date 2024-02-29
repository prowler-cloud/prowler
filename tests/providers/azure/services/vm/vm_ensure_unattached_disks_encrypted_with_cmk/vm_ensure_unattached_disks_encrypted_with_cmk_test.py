from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.vm.vm_service import Disk
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_vm_ensure_unattached_disks_encrypted_with_cmk:
    def test_vm_no_subscriptions(self):
        vm_client = mock.MagicMock
        vm_client.disks = {}

        with mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk import (
                vm_ensure_unattached_disks_encrypted_with_cmk,
            )

            check = vm_ensure_unattached_disks_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0

    def test_vm_subscription_empty(self):
        vm_client = mock.MagicMock
        vm_client.disks = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk import (
                vm_ensure_unattached_disks_encrypted_with_cmk,
            )

            check = vm_ensure_unattached_disks_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0

    def test_vm_one_unattached_disk_encrypt_pk(self):
        disk_id = uuid4()
        resource_id = uuid4()
        vm_client = mock.MagicMock
        vm_client.disks = {
            AZURE_SUBSCRIPTION: {
                disk_id: Disk(
                    resource_id=resource_id,
                    resource_name="test-disk",
                    vms_attached=[],
                    encryption_type="EncryptionAtRestWithPlatformKey",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk import (
                vm_ensure_unattached_disks_encrypted_with_cmk,
            )

            check = vm_ensure_unattached_disks_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].status == "FAIL"
            assert result[0].resource_id == resource_id
            assert result[0].resource_name == "test-disk"
            assert (
                result[0].status_extended
                == f"Disk '{disk_id}' is not encrypted with a customer-managed key in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_vm_one_unattached_disk_encrypt_cmk(self):
        disk_id = uuid4()
        resource_id = uuid4()
        vm_client = mock.MagicMock
        vm_client.disks = {
            AZURE_SUBSCRIPTION: {
                disk_id: Disk(
                    resource_id=resource_id,
                    resource_name="test-disk",
                    vms_attached=[],
                    encryption_type="EncryptionAtRestWithCustomerKey",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk import (
                vm_ensure_unattached_disks_encrypted_with_cmk,
            )

            check = vm_ensure_unattached_disks_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].status == "PASS"
            assert result[0].resource_id == resource_id
            assert result[0].resource_name == "test-disk"
            assert (
                result[0].status_extended
                == f"Disk '{disk_id}' is encrypted with a customer-managed key in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_vm_subscription_two_unattached_disk_encrypt_cmk_and_pk(self):
        disk_id_1 = uuid4()
        resource_id_1 = uuid4()
        disk_id_2 = uuid4()
        resource_id_2 = uuid4()
        vm_client = mock.MagicMock
        vm_client.disks = {
            AZURE_SUBSCRIPTION: {
                disk_id_1: Disk(
                    resource_id=resource_id_1,
                    resource_name="test-disk",
                    vms_attached=[],
                    encryption_type="EncryptionAtRestWithPlatformKey",
                ),
                disk_id_2: Disk(
                    resource_id=resource_id_2,
                    resource_name="test-disk-2",
                    vms_attached=[],
                    encryption_type="EncryptionAtRestWithCustomerKey",
                ),
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk import (
                vm_ensure_unattached_disks_encrypted_with_cmk,
            )

            check = vm_ensure_unattached_disks_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 2
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].status == "FAIL"
            assert result[0].resource_id == resource_id_1
            assert result[0].resource_name == "test-disk"
            assert (
                result[0].status_extended
                == f"Disk '{disk_id_1}' is not encrypted with a customer-managed key in subscription {AZURE_SUBSCRIPTION}."
            )
            assert result[1].status == "PASS"
            assert result[1].resource_id == resource_id_2
            assert result[1].resource_name == "test-disk-2"
            assert (
                result[1].status_extended
                == f"Disk '{disk_id_2}' is encrypted with a customer-managed key in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_vm_attached_disk_encrypt_cmk(self):
        disk_id = uuid4()
        resource_id = uuid4()
        vm_client = mock.MagicMock
        vm_client.disks = {
            AZURE_SUBSCRIPTION: {
                disk_id: Disk(
                    resource_id=resource_id,
                    resource_name="test-disk",
                    vms_attached=[uuid4()],
                    encryption_type="EncryptionAtRestWithCustomerKey",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_unattached_disks_encrypted_with_cmk.vm_ensure_unattached_disks_encrypted_with_cmk import (
                vm_ensure_unattached_disks_encrypted_with_cmk,
            )

            check = vm_ensure_unattached_disks_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0
