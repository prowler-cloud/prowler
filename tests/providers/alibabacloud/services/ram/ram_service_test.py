from unittest.mock import patch
from prowler.providers.alibabacloud.services.ram.ram_service import (
    RAM,
    User,
    PasswordPolicy,
    AccessKey,
)
from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_RAM_Service:
    def test_service(self):
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ):
            ram = RAM(set_mocked_alibabacloud_provider())

            assert ram.service == "ram"
            assert ram.account_id == ALIBABACLOUD_ACCOUNT_ID
            assert ram.region == ALIBABACLOUD_REGION
            assert len(ram.regions) > 0

    def test_user_creation(self):
        user_id = "test-user-123"
        arn = f"acs:ram::{ALIBABACLOUD_ACCOUNT_ID}:user/{user_id}"

        user = User(
            id=user_id,
            name="test-user",
            arn=arn,
            console_login_enabled=True,
            mfa_enabled=True,
            access_keys=[
                AccessKey(
                    access_key_id="LTAI_test123",
                    user_name="test-user",
                    status="Active",
                    create_date="2024-01-01",
                )
            ],
        )

        assert user.id == user_id
        assert user.name == "test-user"
        assert user.arn == arn
        assert user.console_login_enabled is True
        assert user.mfa_enabled is True
        assert len(user.access_keys) == 1
        assert user.access_keys[0].access_key_id == "LTAI_test123"

    def test_password_policy_creation(self):
        policy = PasswordPolicy(
            minimum_length=14,
            require_lowercase=True,
            require_uppercase=True,
            require_numbers=True,
            require_symbols=True,
            max_login_attempts=5,
            max_password_age=90,
            password_reuse_prevention=5,
        )

        assert policy.minimum_length == 14
        assert policy.require_lowercase is True
        assert policy.require_uppercase is True
        assert policy.require_numbers is True
        assert policy.require_symbols is True
        assert policy.max_login_attempts == 5
        assert policy.max_password_age == 90
        assert policy.password_reuse_prevention == 5

    def test_access_key_creation(self):
        access_key = AccessKey(
            access_key_id="LTAI_test",
            user_name="test-user",
            status="Active",
            create_date="2024-01-01",
            last_used_date="2024-12-01",
        )

        assert access_key.access_key_id == "LTAI_test"
        assert access_key.user_name == "test-user"
        assert access_key.status == "Active"
        assert access_key.create_date == "2024-01-01"
        assert access_key.last_used_date == "2024-12-01"
