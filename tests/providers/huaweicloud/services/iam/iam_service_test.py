from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.iam.iam_service import (
    IAM,
    IAMUser,
    MFADevice,
)
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"
DOMAIN_ID = "123456789012"


def _build_client(
    password_policy=None,
    users=None,
    mfa_devices=None,
    operation_protection=True,
):
    """Build a single mock IAM client serving all four IAM fetch calls."""
    client = mock.MagicMock()

    if password_policy is None:
        password_policy = SimpleNamespace(
            minimum_password_length=8,
            maximum_password_length=32,
            minimum_password_age=1,
            password_validity_period=90,
            password_char_combination=3,
            maximum_consecutive_identical_chars=2,
            number_of_recent_passwords_disallowed=5,
            password_not_username_or_invert=True,
        )
    client.show_domain_password_policy.return_value = SimpleNamespace(
        password_policy=password_policy
    )

    if users is None:
        users = []
    client.keystone_list_users.return_value = SimpleNamespace(users=users)

    if mfa_devices is None:
        mfa_devices = []
    client.list_user_mfa_devices.return_value = SimpleNamespace(
        virtual_mfa_devices=mfa_devices
    )

    client.show_domain_protect_policy.return_value = SimpleNamespace(
        protect_policy=SimpleNamespace(operation_protection=operation_protection)
    )

    return client


def _provider_with_client(client):
    """Return a mocked global-service provider whose single client is the mock."""
    provider = set_mocked_huaweicloud_provider(region=REGION, domain_id=DOMAIN_ID)
    provider.session.client = mock.MagicMock(return_value=client)
    return provider


class TestIAMService:
    def test_parses_all_resources(self):
        users = [
            SimpleNamespace(
                id="user-1",
                name="alice",
                enabled=True,
                password_expires_at="2026-12-31T00:00:00Z",
            ),
            SimpleNamespace(
                id="user-2",
                name="bob",
                enabled=False,
                password_expires_at=None,
            ),
        ]
        mfa_devices = [
            SimpleNamespace(serial_number="mfa-serial-1", user_id="user-1"),
        ]
        client = _build_client(
            users=users,
            mfa_devices=mfa_devices,
            operation_protection=True,
        )

        iam = IAM(_provider_with_client(client))

        # Password policy
        assert iam.password_policy.minimum_password_length == 8
        assert iam.password_policy.maximum_password_length == 32
        assert iam.password_policy.minimum_password_age == 1
        assert iam.password_policy.password_validity_period == 90
        assert iam.password_policy.password_char_combination == 3
        assert iam.password_policy.maximum_consecutive_identical_chars == 2
        assert iam.password_policy.number_of_recent_passwords_disallowed == 5
        assert iam.password_policy.password_not_username_or_invert is True

        # Users
        assert len(iam.users) == 2
        assert all(isinstance(u, IAMUser) for u in iam.users)
        alice = iam.users[0]
        assert alice.id == "user-1"
        assert alice.name == "alice"
        assert alice.enabled is True
        assert alice.is_domain_owner is False
        assert alice.password_expires_at == "2026-12-31T00:00:00Z"
        bob = iam.users[1]
        assert bob.name == "bob"
        assert bob.enabled is False

        # MFA devices
        assert len(iam.mfa_devices) == 1
        assert isinstance(iam.mfa_devices[0], MFADevice)
        assert iam.mfa_devices[0].serial_number == "mfa-serial-1"
        assert iam.mfa_devices[0].user_id == "user-1"

        # Operation protection
        assert iam.operation_protection.enabled is True
        assert iam.operation_protection.account_id == DOMAIN_ID

    def test_domain_owner_is_flagged(self):
        users = [
            SimpleNamespace(
                id=DOMAIN_ID,
                name="root",
                enabled=True,
                password_expires_at=None,
            ),
        ]
        client = _build_client(users=users)

        iam = IAM(_provider_with_client(client))

        assert len(iam.users) == 1
        assert iam.users[0].is_domain_owner is True

    def test_operation_protection_disabled(self):
        client = _build_client(operation_protection=False)

        iam = IAM(_provider_with_client(client))

        assert iam.operation_protection.enabled is False

    def test_empty_users_and_mfa_devices(self):
        client = _build_client(users=[], mfa_devices=[])

        iam = IAM(_provider_with_client(client))

        assert iam.users == []
        assert iam.mfa_devices == []

    def test_list_users_sdk_error_is_swallowed(self):
        client = _build_client(
            mfa_devices=[
                SimpleNamespace(serial_number="mfa-serial-1", user_id="user-1")
            ],
            operation_protection=True,
        )
        # keystone_list_users raises; other fetches must still succeed.
        client.keystone_list_users.side_effect = Exception("boom")

        iam = IAM(_provider_with_client(client))

        # Failed fetch leaves its default empty list.
        assert iam.users == []
        # Other fetches unaffected.
        assert iam.password_policy.minimum_password_length == 8
        assert len(iam.mfa_devices) == 1
        assert iam.operation_protection.enabled is True
