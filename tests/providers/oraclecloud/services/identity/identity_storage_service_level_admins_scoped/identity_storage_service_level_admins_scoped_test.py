from datetime import datetime
from unittest import mock

import pytest

from prowler.providers.oraclecloud.services.identity.identity_service import Policy
from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_REGION,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)

CHECK_PATH = "prowler.providers.oraclecloud.services.identity.identity_storage_service_level_admins_scoped.identity_storage_service_level_admins_scoped"


def _policy(name, statements, lifecycle_state="ACTIVE"):
    return Policy(
        id=f"ocid1.policy.oc1..{name.lower().replace(' ', '-')}",
        name=name,
        description="Test policy",
        compartment_id=OCI_COMPARTMENT_ID,
        statements=statements,
        time_created=datetime.now(),
        lifecycle_state=lifecycle_state,
        region=OCI_REGION,
    )


def _identity_client(policies):
    identity_client = mock.MagicMock()
    identity_client.policies = policies
    identity_client.audited_tenancy = OCI_TENANCY_ID
    identity_client.audited_regions = [mock.MagicMock(key=OCI_REGION)]
    return identity_client


def _run_check(policies):
    identity_client = _identity_client(policies)

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oraclecloud_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.identity_client", new=identity_client),
    ):
        from prowler.providers.oraclecloud.services.identity.identity_storage_service_level_admins_scoped.identity_storage_service_level_admins_scoped import (
            identity_storage_service_level_admins_scoped,
        )

        return identity_storage_service_level_admins_scoped().execute()


class Test_identity_storage_service_level_admins_scoped:
    def test_no_policies_passes_with_tenancy_finding(self):
        result = _run_check([])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == OCI_TENANCY_ID
        assert result[0].resource_name == "Tenancy"
        assert (
            result[0].status_extended
            == "No active storage service-level administrator policies grant manage permissions without excluding delete permissions."
        )

    def test_manage_volumes_without_delete_exclusion_fails(self):
        result = _run_check(
            [
                _policy(
                    "Volume Admins",
                    ["Allow group VolumeUsers to manage volumes in tenancy"],
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_name == "Volume Admins"
        assert "VOLUME_DELETE" in result[0].status_extended
        assert (
            "Allow group VolumeUsers to manage volumes in tenancy"
            in result[0].status_extended
        )

    def test_manage_volumes_with_delete_exclusion_passes(self):
        result = _run_check(
            [
                _policy(
                    "Volume Admins",
                    [
                        "Allow group VolumeUsers to manage volumes in tenancy where request.permission!='VOLUME_DELETE'"
                    ],
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Policy 'Volume Admins' excludes required storage delete permissions from storage manage statements."
        )

    def test_delete_exclusion_parser_is_case_and_whitespace_insensitive(self):
        result = _run_check(
            [
                _policy(
                    "Volume Admins",
                    [
                        "  allow   group VolumeUsers TO   manage   volumes in tenancy WHERE request.permission   !=   'volume_delete'  "
                    ],
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_generic_where_clause_does_not_pass(self):
        result = _run_check(
            [
                _policy(
                    "Bucket Admins",
                    [
                        "Allow group BucketUsers to manage buckets in tenancy where request.region='iad'"
                    ],
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "BUCKET_DELETE" in result[0].status_extended
        assert "request.region='iad'" in result[0].status_extended

    @pytest.mark.parametrize(
        "statement",
        [
            "Allow group BucketUsers to manage buckets in tenancy where ANY {request.permission!='BUCKET_DELETE', request.region='iad'}",
            "Allow group BucketUsers to manage buckets in tenancy where request.permission!='BUCKET_DELETE' OR request.region='iad'",
        ],
    )
    def test_disjunctive_delete_exclusion_does_not_pass(self, statement):
        result = _run_check([_policy("Bucket Admins", [statement])])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "BUCKET_DELETE" in result[0].status_extended

    @pytest.mark.parametrize(
        "resource,permission",
        [
            ("file-systems", "FILE_SYSTEM_DELETE"),
            ("mount-targets", "MOUNT_TARGET_DELETE"),
            ("export-sets", "EXPORT_SET_DELETE"),
            ("volumes", "VOLUME_DELETE"),
            ("volume-backups", "VOLUME_BACKUP_DELETE"),
            ("objects", "OBJECT_DELETE"),
            ("buckets", "BUCKET_DELETE"),
        ],
    )
    def test_storage_resources_require_matching_delete_exclusion(
        self, resource, permission
    ):
        fail_result = _run_check(
            [
                _policy(
                    "Storage Admins",
                    [f"Allow group StorageUsers to manage {resource} in tenancy"],
                )
            ]
        )
        pass_result = _run_check(
            [
                _policy(
                    "Storage Admins",
                    [
                        f"Allow group StorageUsers to manage {resource} in tenancy where request.permission != '{permission}'"
                    ],
                )
            ]
        )

        assert len(fail_result) == 1
        assert fail_result[0].status == "FAIL"
        assert permission in fail_result[0].status_extended
        assert len(pass_result) == 1
        assert pass_result[0].status == "PASS"

    def test_file_family_fails_until_all_delete_permissions_are_excluded(self):
        partial_result = _run_check(
            [
                _policy(
                    "File Admins",
                    [
                        "Allow group FileUsers to manage file-family in tenancy where ALL {request.permission!='FILE_SYSTEM_DELETE', request.permission!='MOUNT_TARGET_DELETE'}"
                    ],
                )
            ]
        )
        complete_result = _run_check(
            [
                _policy(
                    "File Admins",
                    [
                        "Allow group FileUsers to manage file-family in tenancy where ALL {request.permission!='FILE_SYSTEM_DELETE', request.permission!='MOUNT_TARGET_DELETE', request.permission!='EXPORT_SET_DELETE'}"
                    ],
                )
            ]
        )

        assert len(partial_result) == 1
        assert partial_result[0].status == "FAIL"
        assert "EXPORT_SET_DELETE" in partial_result[0].status_extended
        assert len(complete_result) == 1
        assert complete_result[0].status == "PASS"

    @pytest.mark.parametrize(
        "family,missing_permission,statement",
        [
            (
                "volume-family",
                "VOLUME_BACKUP_DELETE",
                "Allow group VolumeUsers to manage volume-family in tenancy where request.permission!='VOLUME_DELETE'",
            ),
            (
                "object-family",
                "BUCKET_DELETE",
                "Allow group BucketUsers to manage object-family in tenancy where request.permission!='OBJECT_DELETE'",
            ),
            (
                "all-resources",
                "BUCKET_DELETE",
                "Allow group StorageUsers to manage all-resources in tenancy where ALL {request.permission!='VOLUME_DELETE', request.permission!='VOLUME_BACKUP_DELETE', request.permission!='FILE_SYSTEM_DELETE', request.permission!='MOUNT_TARGET_DELETE', request.permission!='EXPORT_SET_DELETE', request.permission!='OBJECT_DELETE'}",
            ),
        ],
    )
    def test_families_and_all_resources_fail_unless_all_delete_permissions_are_excluded(
        self, family, missing_permission, statement
    ):
        result = _run_check([_policy("Storage Admins", [statement])])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert family in result[0].status_extended
        assert missing_permission in result[0].status_extended

    def test_all_resources_passes_when_all_storage_delete_permissions_are_excluded(
        self,
    ):
        result = _run_check(
            [
                _policy(
                    "Storage Admins",
                    [
                        "Allow group StorageUsers to manage all-resources in tenancy where ALL {request.permission!='VOLUME_DELETE', request.permission!='VOLUME_BACKUP_DELETE', request.permission!='FILE_SYSTEM_DELETE', request.permission!='MOUNT_TARGET_DELETE', request.permission!='EXPORT_SET_DELETE', request.permission!='OBJECT_DELETE', request.permission!='BUCKET_DELETE'}"
                    ],
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_inactive_policies_are_ignored(self):
        result = _run_check(
            [
                _policy(
                    "Inactive Volume Admins",
                    ["Allow group VolumeUsers to manage volumes in tenancy"],
                    lifecycle_state="INACTIVE",
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_name == "Tenancy"

    def test_tenant_admin_policy_is_ignored(self):
        result = _run_check(
            [
                _policy(
                    "Tenant Admin Policy",
                    ["Allow group Administrators to manage all-resources in tenancy"],
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_name == "Tenancy"
