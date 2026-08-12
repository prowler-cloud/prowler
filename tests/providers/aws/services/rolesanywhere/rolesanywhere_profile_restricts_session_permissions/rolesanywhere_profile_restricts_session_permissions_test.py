from types import SimpleNamespace
from unittest import mock

from prowler.providers.aws.services.rolesanywhere.rolesanywhere_service import Profile
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

PROFILE_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PROFILE_NAME = "workload-profile"
PROFILE_ARN = f"arn:aws:rolesanywhere:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:profile/{PROFILE_ID}"
ADMIN_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/admin-role"
READONLY_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/workload-role"
UNKNOWN_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/cross-account-role"
CUSTOM_ADMIN_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/custom-admin-role"
INLINE_ADMIN_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/inline-admin-role"
NAME_COLLISION_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/name-collision-role"
UNRESOLVED_POLICY_ROLE_ARN = (
    f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/unresolved-policy-role"
)
AWS_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
CUSTOMER_ADMIN_NAMED_POLICY_ARN = (
    f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/AdministratorAccess"
)
CUSTOM_ADMIN_POLICY_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/custom-admin"
MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"

SESSION_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Action":["s3:GetObject"],"Resource":["*"]}]}'
)
FULL_ACCESS_SESSION_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Action":"*","Resource":"*"}]}'
)

FULL_ACCESS_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
READONLY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}],
}


def _profile(
    *,
    enabled: bool = True,
    session_policy: str = "",
    managed_policy_arns=None,
    role_arns=None,
):
    return Profile(
        arn=PROFILE_ARN,
        id=PROFILE_ID,
        name=PROFILE_NAME,
        region=AWS_REGION_US_EAST_1,
        enabled=enabled,
        role_arns=role_arns if role_arns is not None else [READONLY_ROLE_ARN],
        session_policy=session_policy,
        managed_policy_arns=managed_policy_arns or [],
    )


def _role(arn, attached_policies=None, inline_policies=None):
    return SimpleNamespace(
        arn=arn,
        attached_policies=attached_policies or [],
        inline_policies=inline_policies or [],
    )


def _iam_client():
    """IAM client stub mirroring iam_service models: roles with attached/inline
    policies and a policies dict keyed by ARN (inline keyed {role_arn}:policy/{name}).
    """
    roles = [
        _role(
            ADMIN_ROLE_ARN,
            attached_policies=[
                {"PolicyName": "AdministratorAccess", "PolicyArn": AWS_ADMIN_POLICY_ARN}
            ],
        ),
        _role(
            READONLY_ROLE_ARN,
            attached_policies=[
                {"PolicyName": "ReadOnlyAccess", "PolicyArn": MANAGED_POLICY_ARN}
            ],
        ),
        _role(
            CUSTOM_ADMIN_ROLE_ARN,
            attached_policies=[
                {"PolicyName": "custom-admin", "PolicyArn": CUSTOM_ADMIN_POLICY_ARN}
            ],
        ),
        _role(INLINE_ADMIN_ROLE_ARN, inline_policies=["inline-admin"]),
        _role(
            NAME_COLLISION_ROLE_ARN,
            attached_policies=[
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": CUSTOMER_ADMIN_NAMED_POLICY_ARN,
                }
            ],
        ),
        _role(
            UNRESOLVED_POLICY_ROLE_ARN,
            attached_policies=[
                {
                    "PolicyName": "unresolved",
                    "PolicyArn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/unresolved",
                }
            ],
        ),
    ]
    policies = {
        AWS_ADMIN_POLICY_ARN: SimpleNamespace(document=FULL_ACCESS_DOCUMENT),
        CUSTOM_ADMIN_POLICY_ARN: SimpleNamespace(document=FULL_ACCESS_DOCUMENT),
        MANAGED_POLICY_ARN: SimpleNamespace(document=READONLY_DOCUMENT),
        # Customer-managed policy that merely shares the AdministratorAccess name.
        CUSTOMER_ADMIN_NAMED_POLICY_ARN: SimpleNamespace(document=READONLY_DOCUMENT),
        f"{INLINE_ADMIN_ROLE_ARN}:policy/inline-admin": SimpleNamespace(
            document=FULL_ACCESS_DOCUMENT
        ),
    }
    iam = mock.MagicMock()
    iam.roles = roles
    iam.policies = policies
    return iam


def _build_client(profiles):
    ra_client = mock.MagicMock()
    ra_client.profiles = profiles
    return ra_client


def _patched(ra_client):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    check_module = "prowler.providers.aws.services.rolesanywhere.rolesanywhere_profile_restricts_session_permissions.rolesanywhere_profile_restricts_session_permissions"
    return [
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{check_module}.rolesanywhere_client", new=ra_client),
        mock.patch(f"{check_module}.iam_client", new=_iam_client()),
    ]


def _enter(patches):
    from contextlib import ExitStack

    stack = ExitStack()
    for p in patches:
        stack.enter_context(p)
    return stack


def _run():
    from prowler.providers.aws.services.rolesanywhere.rolesanywhere_profile_restricts_session_permissions.rolesanywhere_profile_restricts_session_permissions import (
        rolesanywhere_profile_restricts_session_permissions,
    )

    return rolesanywhere_profile_restricts_session_permissions().execute()


class Test_rolesanywhere_profile_restricts_session_permissions:
    def test_no_profiles(self):
        with _enter(_patched(_build_client({}))):
            assert len(_run()) == 0

    def test_unscoped_profile_with_admin_role_fails(self):
        with _enter(
            _patched(_build_client({PROFILE_ARN: _profile(role_arns=[ADMIN_ROLE_ARN])}))
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == PROFILE_ID
            assert result[0].resource_arn == PROFILE_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
            assert ADMIN_ROLE_ARN in result[0].status_extended
            assert "administrative" in result[0].status_extended

    def test_unscoped_profile_with_custom_admin_policy_fails(self):
        with _enter(
            _patched(
                _build_client(
                    {PROFILE_ARN: _profile(role_arns=[CUSTOM_ADMIN_ROLE_ARN])}
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert CUSTOM_ADMIN_ROLE_ARN in result[0].status_extended

    def test_unscoped_profile_with_inline_admin_policy_fails(self):
        with _enter(
            _patched(
                _build_client(
                    {PROFILE_ARN: _profile(role_arns=[INLINE_ADMIN_ROLE_ARN])}
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert INLINE_ADMIN_ROLE_ARN in result[0].status_extended

    def test_mixed_roles_fail_lists_only_admin_role(self):
        with _enter(
            _patched(
                _build_client(
                    {
                        PROFILE_ARN: _profile(
                            role_arns=[READONLY_ROLE_ARN, ADMIN_ROLE_ARN]
                        )
                    }
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert ADMIN_ROLE_ARN in result[0].status_extended
            assert READONLY_ROLE_ARN not in result[0].status_extended

    def test_customer_policy_named_administratoraccess_passes(self):
        # Name collision: customer-managed policy called AdministratorAccess
        # whose document is read-only must not flag the role as administrative.
        with _enter(
            _patched(
                _build_client(
                    {PROFILE_ARN: _profile(role_arns=[NAME_COLLISION_ROLE_ARN])}
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_unresolved_attached_policy_passes(self):
        # Attached policy ARN missing from iam_client.policies (document None path).
        with _enter(
            _patched(
                _build_client(
                    {PROFILE_ARN: _profile(role_arns=[UNRESOLVED_POLICY_ROLE_ARN])}
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_unscoped_profile_with_least_privilege_role_passes(self):
        with _enter(
            _patched(
                _build_client({PROFILE_ARN: _profile(role_arns=[READONLY_ROLE_ARN])})
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "defense-in-depth" in result[0].status_extended

    def test_unscoped_profile_with_unknown_role_passes(self):
        with _enter(
            _patched(
                _build_client({PROFILE_ARN: _profile(role_arns=[UNKNOWN_ROLE_ARN])})
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no referenced role was identified" in result[0].status_extended

    def test_unscoped_profile_without_roles_passes(self):
        with _enter(_patched(_build_client({PROFILE_ARN: _profile(role_arns=[])}))):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_profile_with_session_policy_passes(self):
        with _enter(
            _patched(
                _build_client(
                    {
                        PROFILE_ARN: _profile(
                            session_policy=SESSION_POLICY, role_arns=[ADMIN_ROLE_ARN]
                        )
                    }
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "session policy" in result[0].status_extended

    def test_full_access_session_policy_does_not_scope(self):
        # A sessionPolicy granting *:* does not restrict anything.
        with _enter(
            _patched(
                _build_client(
                    {
                        PROFILE_ARN: _profile(
                            session_policy=FULL_ACCESS_SESSION_POLICY,
                            role_arns=[ADMIN_ROLE_ARN],
                        )
                    }
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_profile_with_managed_policies_passes(self):
        with _enter(
            _patched(
                _build_client(
                    {
                        PROFILE_ARN: _profile(
                            managed_policy_arns=[MANAGED_POLICY_ARN],
                            role_arns=[ADMIN_ROLE_ARN],
                        )
                    }
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_admin_managed_session_policy_does_not_scope(self):
        # AdministratorAccess as the managed session policy restricts nothing.
        with _enter(
            _patched(
                _build_client(
                    {
                        PROFILE_ARN: _profile(
                            managed_policy_arns=[AWS_ADMIN_POLICY_ARN],
                            role_arns=[ADMIN_ROLE_ARN],
                        )
                    }
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_restrictive_inline_with_admin_managed_policy_fails(self):
        # The session-policy set is evaluated as a union: AdministratorAccess as
        # a managed session policy makes the boundary unrestricted even though
        # the inline session policy is restrictive.
        with _enter(
            _patched(
                _build_client(
                    {
                        PROFILE_ARN: _profile(
                            session_policy=SESSION_POLICY,
                            managed_policy_arns=[AWS_ADMIN_POLICY_ARN],
                            role_arns=[ADMIN_ROLE_ARN],
                        )
                    }
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_full_access_inline_with_restrictive_managed_policy_fails(self):
        # Conversely, a *:* inline session policy leaves the union unrestricted
        # regardless of a restrictive managed session policy.
        with _enter(
            _patched(
                _build_client(
                    {
                        PROFILE_ARN: _profile(
                            session_policy=FULL_ACCESS_SESSION_POLICY,
                            managed_policy_arns=[MANAGED_POLICY_ARN],
                            role_arns=[ADMIN_ROLE_ARN],
                        )
                    }
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_restrictive_inline_and_restrictive_managed_policy_passes(self):
        with _enter(
            _patched(
                _build_client(
                    {
                        PROFILE_ARN: _profile(
                            session_policy=SESSION_POLICY,
                            managed_policy_arns=[MANAGED_POLICY_ARN],
                            role_arns=[ADMIN_ROLE_ARN],
                        )
                    }
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_disabled_profile_passes(self):
        with _enter(
            _patched(
                _build_client(
                    {PROFILE_ARN: _profile(enabled=False, role_arns=[ADMIN_ROLE_ARN])}
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "disabled" in result[0].status_extended
