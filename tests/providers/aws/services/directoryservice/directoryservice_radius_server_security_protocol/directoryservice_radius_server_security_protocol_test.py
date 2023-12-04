from unittest import mock

from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    AuthenticationProtocol,
    Directory,
    DirectoryType,
    RadiusSettings,
    RadiusStatus,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)


class Test_directoryservice_radius_server_security_protocol:
    def test_no_directories(self):
        directoryservice_client = mock.MagicMock
        directoryservice_client.directories = {}
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_radius_server_security_protocol.directoryservice_radius_server_security_protocol import (
                directoryservice_radius_server_security_protocol,
            )

            check = directoryservice_radius_server_security_protocol()
            result = check.execute()

            assert len(result) == 0

    def test_directory_no_radius_server(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                radius_settings=None,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_radius_server_security_protocol.directoryservice_radius_server_security_protocol import (
                directoryservice_radius_server_security_protocol,
            )

            check = directoryservice_radius_server_security_protocol()
            result = check.execute()

            assert len(result) == 0

    def test_directory_radius_server_bad_auth_protocol(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                radius_settings=RadiusSettings(
                    authentication_protocol=AuthenticationProtocol.MS_CHAPv1,
                    status=RadiusStatus.Completed,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_radius_server_security_protocol.directoryservice_radius_server_security_protocol import (
                directoryservice_radius_server_security_protocol,
            )

            check = directoryservice_radius_server_security_protocol()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Radius server of Directory {directory_id} does not have recommended security protocol for the Radius server."
            )

    def test_directory_radius_server_secure_auth_protocol(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
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
            from prowler.providers.aws.services.directoryservice.directoryservice_radius_server_security_protocol.directoryservice_radius_server_security_protocol import (
                directoryservice_radius_server_security_protocol,
            )

            check = directoryservice_radius_server_security_protocol()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Radius server of Directory {directory_id} have recommended security protocol for the Radius server."
            )
