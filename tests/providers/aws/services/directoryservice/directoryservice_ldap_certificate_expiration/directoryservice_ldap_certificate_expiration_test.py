from datetime import datetime
from unittest import mock

from freezegun import freeze_time

from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    Certificate,
    CertificateState,
    CertificateType,
    Directory,
    DirectoryType,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)


# Always use a mocked date to test the certificates expiration
@freeze_time("2023-01-01")
class Test_directoryservice_ldap_certificate_expiration:
    def test_no_directories(self):
        directoryservice_client = mock.MagicMock
        directoryservice_client.directories = {}
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_ldap_certificate_expiration.directoryservice_ldap_certificate_expiration import (
                directoryservice_ldap_certificate_expiration,
            )

            check = directoryservice_ldap_certificate_expiration()
            result = check.execute()

            assert len(result) == 0

    def test_directory_no_certificate(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        directoryservice_client.directories = {
            directory_name: Directory(
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                name=directory_name,
                region=AWS_REGION_EU_WEST_1,
                certificates=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_ldap_certificate_expiration.directoryservice_ldap_certificate_expiration import (
                directoryservice_ldap_certificate_expiration,
            )

            check = directoryservice_ldap_certificate_expiration()
            result = check.execute()

            assert len(result) == 0

    def test_directory_certificate_expires_in_365_days(self):
        remaining_days_to_expire = 365

        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        certificate_id = "test-certificate"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                certificates=[
                    Certificate(
                        id=certificate_id,
                        common_name=certificate_id,
                        state=CertificateState.Registered,
                        type=CertificateType.ClientLDAPS,
                        expiry_date_time=datetime(2024, 1, 1),
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_ldap_certificate_expiration.directoryservice_ldap_certificate_expiration import (
                directoryservice_ldap_certificate_expiration,
            )

            check = directoryservice_ldap_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == certificate_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"LDAP Certificate {certificate_id} configured at {directory_id} expires in {remaining_days_to_expire} days."
            )

    def test_directory_certificate_expires_in_90_days(self):
        remaining_days_to_expire = 90

        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        certificate_id = "test-certificate"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                certificates=[
                    Certificate(
                        id=certificate_id,
                        common_name=certificate_id,
                        state=CertificateState.Registered,
                        type=CertificateType.ClientLDAPS,
                        expiry_date_time=datetime(2023, 4, 1),
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_ldap_certificate_expiration.directoryservice_ldap_certificate_expiration import (
                directoryservice_ldap_certificate_expiration,
            )

            check = directoryservice_ldap_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == certificate_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"LDAP Certificate {certificate_id} configured at {directory_id} is about to expire in {remaining_days_to_expire} days."
            )

    def test_directory_certificate_expires_in_31_days(self):
        remaining_days_to_expire = 31

        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        certificate_id = "test-certificate"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                certificates=[
                    Certificate(
                        id=certificate_id,
                        common_name=certificate_id,
                        state=CertificateState.Registered,
                        type=CertificateType.ClientLDAPS,
                        expiry_date_time=datetime(2023, 2, 1),
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_ldap_certificate_expiration.directoryservice_ldap_certificate_expiration import (
                directoryservice_ldap_certificate_expiration,
            )

            check = directoryservice_ldap_certificate_expiration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == certificate_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"LDAP Certificate {certificate_id} configured at {directory_id} is about to expire in {remaining_days_to_expire} days."
            )
