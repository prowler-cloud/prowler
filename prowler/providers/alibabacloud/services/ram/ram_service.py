"""
Alibaba Cloud RAM Service

This module provides the service class for Alibaba Cloud Resource Access Management (RAM).
"""

from dataclasses import dataclass
from typing import Optional

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class User:
    """RAM User"""
    id: str
    name: str
    arn: str
    create_date: str = ""
    console_login_enabled: bool = False
    mfa_enabled: bool = False
    access_keys: list = None
    attached_policies: list = None
    groups: list = None
    last_login_date: str = ""

    def __post_init__(self):
        if self.access_keys is None:
            self.access_keys = []
        if self.attached_policies is None:
            self.attached_policies = []
        if self.groups is None:
            self.groups = []


@dataclass
class PasswordPolicy:
    """RAM Password Policy"""
    minimum_length: int = 8
    require_lowercase: bool = False
    require_uppercase: bool = False
    require_numbers: bool = False
    require_symbols: bool = False
    max_login_attempts: int = 5
    max_password_age: int = 0  # 0 = no expiration
    password_reuse_prevention: int = 0  # 0 = no prevention
    hard_expiry: bool = False


@dataclass
class AccessKey:
    """RAM Access Key"""
    access_key_id: str
    user_name: str
    status: str = "Active"
    create_date: str = ""
    last_used_date: str = ""


class RAM(AlibabaCloudService):
    """
    Alibaba Cloud RAM service class

    Handles collection of RAM resources including users, password policies,
    access keys, and root account configuration.
    """

    def __init__(self, provider):
        """Initialize RAM service"""
        super().__init__("ram", provider)

        self.users = {}
        self.password_policy = None
        self.root_mfa_enabled = False
        self.root_has_access_keys = False
        self.root_last_activity = None

        logger.info("Collecting RAM users...")
        self._list_users()

        logger.info("Collecting RAM password policy...")
        self._get_password_policy()

        logger.info("Checking root account configuration...")
        self._check_root_account()

        logger.info(
            f"RAM service initialized - Users: {len(self.users)}"
        )

    def _list_users(self):
        """List all RAM users"""
        for region in self.regions:
            try:
                # TODO: Implement actual SDK call
                # Placeholder: Create sample users for demonstration
                user_id = f"ram-user-sample-{region}"
                arn = self.generate_resource_arn("user", user_id, "")

                user = User(
                    id=user_id,
                    name=f"sample-user-{region}",
                    arn=arn,
                    console_login_enabled=True,
                    mfa_enabled=False,  # Will trigger MFA check
                    access_keys=[
                        AccessKey(
                            access_key_id="LTAI_sample",
                            user_name=f"sample-user-{region}",
                            create_date="2023-01-01"
                        )
                    ],
                    attached_policies=[
                        {"PolicyName": "AdministratorAccess", "PolicyType": "System"}
                    ]
                )

                self.users[arn] = user

            except Exception as error:
                self._handle_api_error(error, "ListUsers", region)

    def _get_password_policy(self):
        """Get RAM password policy"""
        try:
            # TODO: Implement actual SDK call
            # Placeholder: Create sample policy
            self.password_policy = PasswordPolicy(
                minimum_length=8,  # Should be 14
                require_lowercase=False,  # Should be True
                require_uppercase=False,  # Should be True
                require_numbers=False,  # Should be True
                require_symbols=False,  # Should be True
                max_login_attempts=5,
                max_password_age=0,  # Should be 90
                password_reuse_prevention=0  # Should be >0
            )

        except Exception as error:
            self._handle_api_error(error, "GetPasswordPolicy", "global")

    def _check_root_account(self):
        """Check root account configuration"""
        try:
            # TODO: Implement actual SDK calls
            # Placeholder values
            self.root_mfa_enabled = False  # Should be True
            self.root_has_access_keys = True  # Should be False
            self.root_last_activity = "2024-01-01"

        except Exception as error:
            self._handle_api_error(error, "CheckRootAccount", "global")
