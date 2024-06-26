from unittest import mock

from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    AuthenticationProtocol,
    Directory,
    DirectoryType,
    RadiusSettings,
    RadiusStatus,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_directoryservice_supported_mfa_radius_enabled:
    def test_no_directories(self):
        directoryservice_client = mock.MagicMock
        directoryservice_client.directories = {}
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_supported_mfa_radius_enabled.directoryservice_supported_mfa_radius_enabled import (
                directoryservice_supported_mfa_radius_enabled,
            )

            check = directoryservice_supported_mfa_radius_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_directory_no_radius_server(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = (
            f"arn:aws:ds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        )
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION,
                radius_settings=None,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_supported_mfa_radius_enabled.directoryservice_supported_mfa_radius_enabled import (
                directoryservice_supported_mfa_radius_enabled,
            )

            check = directoryservice_supported_mfa_radius_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_directory_radius_server_status_failed(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = (
            f"arn:aws:ds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        )
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION,
                radius_settings=RadiusSettings(
                    authentication_protocol=AuthenticationProtocol.MS_CHAPv1,
                    status=RadiusStatus.Failed,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_supported_mfa_radius_enabled.directoryservice_supported_mfa_radius_enabled import (
                directoryservice_supported_mfa_radius_enabled,
            )

            check = directoryservice_supported_mfa_radius_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Directory {directory_id} does not have Radius MFA enabled."
            )

    def test_directory_radius_server_status_creating(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = (
            f"arn:aws:ds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        )
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION,
                radius_settings=RadiusSettings(
                    authentication_protocol=AuthenticationProtocol.MS_CHAPv2,
                    status=RadiusStatus.Creating,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_supported_mfa_radius_enabled.directoryservice_supported_mfa_radius_enabled import (
                directoryservice_supported_mfa_radius_enabled,
            )

            check = directoryservice_supported_mfa_radius_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Directory {directory_id} does not have Radius MFA enabled."
            )

    def test_directory_radius_server_status_completed(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = (
            f"arn:aws:ds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        )
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION,
                radius_settings=RadiusSettings(
                    authentication_protocol=AuthenticationProtocol.MS_CHAPv2,
                    status=RadiusStatus.Completed,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_supported_mfa_radius_enabled.directoryservice_supported_mfa_radius_enabled import (
                directoryservice_supported_mfa_radius_enabled,
            )

            check = directoryservice_supported_mfa_radius_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Directory {directory_id} have Radius MFA enabled."
            )
