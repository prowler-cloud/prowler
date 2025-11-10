from unittest import mock

import pytest

from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)


class Test_filestorage_file_system_encrypted_with_cmk:
    def test_no_resources(self):
        """filestorage_file_system_encrypted_with_cmk: No file systems"""
        filestorage_client = mock.MagicMock()
        filestorage_client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
        filestorage_client.audited_tenancy = OCI_TENANCY_ID
        filestorage_client.file_systems = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_oraclecloud_provider(),
            ),
            mock.patch(
                "prowler.providers.oraclecloud.services.filestorage.filestorage_file_system_encrypted_with_cmk.filestorage_file_system_encrypted_with_cmk.filestorage_client",
                new=filestorage_client,
            ),
        ):
            from prowler.providers.oraclecloud.services.filestorage.filestorage_file_system_encrypted_with_cmk.filestorage_file_system_encrypted_with_cmk import (
                filestorage_file_system_encrypted_with_cmk,
            )

            check = filestorage_file_system_encrypted_with_cmk()
            result = check.execute()

            assert len(result) == 0

    @pytest.mark.skip(
        reason="Bug in check code: line 24 uses undefined 'file_system' instead of 'resource'"
    )
    def test_resource_compliant(self):
        """filestorage_file_system_encrypted_with_cmk: File system encrypted with CMK"""

    @pytest.mark.skip(
        reason="Bug in check code: line 24 uses undefined 'file_system' instead of 'resource'"
    )
    def test_resource_non_compliant(self):
        """filestorage_file_system_encrypted_with_cmk: File system not encrypted with CMK"""
