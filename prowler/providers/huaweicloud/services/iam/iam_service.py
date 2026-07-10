from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class IAM(HuaweiCloudService):
    """
    IAM (Identity and Access Management) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud IAM service
    to retrieve account password policy, users, and MFA devices.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=True)

        self.password_policy = PasswordPolicy()
        self.users: List[IAMUser] = []
        self.mfa_devices: List[MFADevice] = []
        self.domain_id = provider.identity.domain_id if provider.identity else ""

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._get_password_policy()
        self._list_users()
        self._list_mfa_devices()

    def _load_mock_data(self):
        """Load mock data for testing."""
        self.password_policy = PasswordPolicy(
            minimum_password_length=8,
            maximum_password_length=32,
            minimum_password_age=0,
            password_validity_period=90,
            password_char_combination=3,
            maximum_consecutive_identical_chars=3,
            number_of_recent_passwords_disallowed=3,
            password_not_username_or_invert=True,
        )
        self.users = [
            IAMUser(
                id=self.domain_id or "domain-owner-id",
                name="root",
                enabled=True,
                is_domain_owner=True,
            ),
            IAMUser(
                id="user-mock-001",
                name="admin-user",
                enabled=True,
                is_domain_owner=False,
            ),
            IAMUser(
                id="user-mock-002",
                name="dev-user",
                enabled=True,
                is_domain_owner=False,
            ),
        ]
        self.mfa_devices = [
            MFADevice(
                serial_number="iam:virtual-mfa:domain-owner-id",
                user_id=self.domain_id or "domain-owner-id",
            ),
            MFADevice(
                serial_number="iam:virtual-mfa:user-mock-001",
                user_id="user-mock-001",
            ),
        ]

    def _get_password_policy(self):
        """Get the domain password policy."""
        if not self.regional_clients:
            return

        region = list(self.regional_clients.keys())[0]
        client = self.regional_clients[region]
        logger.info(f"IAM - Getting Password Policy from {region}...")

        try:
            from huaweicloudsdkiam.v3 import ShowDomainPasswordPolicyRequest

            request = ShowDomainPasswordPolicyRequest()
            response = self._call_with_retries(
                client.show_domain_password_policy, request
            )

            if response and response.password_policy:
                policy = response.password_policy
                self.password_policy = PasswordPolicy(
                    minimum_password_length=getattr(policy, "minimum_password_length", 0) or 0,
                    maximum_password_length=getattr(policy, "maximum_password_length", 0) or 0,
                    minimum_password_age=getattr(policy, "minimum_password_age", 0) or 0,
                    password_validity_period=getattr(policy, "password_validity_period", 0) or 0,
                    password_char_combination=getattr(policy, "password_char_combination", 0) or 0,
                    maximum_consecutive_identical_chars=getattr(policy, "maximum_consecutive_identical_chars", 0) or 0,
                    number_of_recent_passwords_disallowed=getattr(policy, "number_of_recent_passwords_disallowed", 0) or 0,
                    password_not_username_or_invert=getattr(policy, "password_not_username_or_invert", False) or False,
                )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_users(self):
        """List all IAM users in the domain."""
        if not self.regional_clients:
            return

        region = list(self.regional_clients.keys())[0]
        client = self.regional_clients[region]
        logger.info(f"IAM - Listing Users in {region}...")

        try:
            from huaweicloudsdkiam.v3 import KeystoneListUsersRequest

            request = KeystoneListUsersRequest()
            response = self._call_with_retries(
                client.keystone_list_users, request
            )

            if response and response.users:
                for user_data in response.users:
                    if not self.audit_resources or is_resource_filtered(
                        user_data.id, self.audit_resources
                    ):
                        self.users.append(
                            IAMUser(
                                id=user_data.id,
                                name=getattr(user_data, "name", user_data.id),
                                enabled=getattr(user_data, "enabled", True),
                                is_domain_owner=(user_data.id == self.domain_id),
                                password_expires_at=getattr(user_data, "password_expires_at", None),
                            )
                        )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_mfa_devices(self):
        """List all virtual MFA devices in the domain."""
        if not self.regional_clients:
            return

        region = list(self.regional_clients.keys())[0]
        client = self.regional_clients[region]
        logger.info(f"IAM - Listing MFA Devices in {region}...")

        try:
            from huaweicloudsdkiam.v3 import ListUserMfaDevicesRequest

            request = ListUserMfaDevicesRequest()
            response = self._call_with_retries(
                client.list_user_mfa_devices, request
            )

            if response and response.virtual_mfa_devices:
                for device_data in response.virtual_mfa_devices:
                    self.mfa_devices.append(
                        MFADevice(
                            serial_number=getattr(device_data, "serial_number", ""),
                            user_id=getattr(device_data, "user_id", ""),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class PasswordPolicy(BaseModel):
    """IAM Password Policy model."""

    minimum_password_length: int = 0
    maximum_password_length: int = 0
    minimum_password_age: int = 0
    password_validity_period: int = 0
    password_char_combination: int = 0
    maximum_consecutive_identical_chars: int = 0
    number_of_recent_passwords_disallowed: int = 0
    password_not_username_or_invert: bool = False


class IAMUser(BaseModel):
    """IAM User model."""

    id: str
    name: str
    enabled: bool = True
    is_domain_owner: bool = False
    password_expires_at: Optional[str] = None


class MFADevice(BaseModel):
    """IAM MFA Device model."""

    serial_number: str
    user_id: str
