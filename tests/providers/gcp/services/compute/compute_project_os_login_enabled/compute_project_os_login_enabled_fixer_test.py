from unittest import mock


class TestComputeProjectOsLoginEnabledFixer:
    def test_fix_success(self):
        compute_client_mock = mock.MagicMock()
        set_metadata_mock = (
            compute_client_mock.client.projects().setCommonInstanceMetadata
        )
        set_metadata_mock.return_value.execute.return_value = None

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock.MagicMock(),
        ):
            with mock.patch(
                "prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled_fixer.compute_client",
                new=compute_client_mock,
            ):
                from prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled_fixer import (
                    ComputeProjectOsLoginEnabledFixer,
                )

                fixer = ComputeProjectOsLoginEnabledFixer()
                assert fixer.fix(project_id="test-project")
                set_metadata_mock.assert_called_once_with(
                    project="test-project",
                    body={"items": [{"key": "enable-oslogin", "value": "TRUE"}]},
                )
                set_metadata_mock.return_value.execute.assert_called_once()

    def test_fix_exception(self):
        compute_client_mock = mock.MagicMock()
        set_metadata_mock = (
            compute_client_mock.client.projects().setCommonInstanceMetadata
        )
        set_metadata_mock.side_effect = Exception("fail")

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock.MagicMock(),
        ):
            with mock.patch(
                "prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled_fixer.compute_client",
                new=compute_client_mock,
            ):
                from prowler.providers.gcp.services.compute.compute_project_os_login_enabled.compute_project_os_login_enabled_fixer import (
                    ComputeProjectOsLoginEnabledFixer,
                )

                fixer = ComputeProjectOsLoginEnabledFixer()
                assert not fixer.fix(project_id="test-project")
                set_metadata_mock.assert_called_once_with(
                    project="test-project",
                    body={"items": [{"key": "enable-oslogin", "value": "TRUE"}]},
                )
