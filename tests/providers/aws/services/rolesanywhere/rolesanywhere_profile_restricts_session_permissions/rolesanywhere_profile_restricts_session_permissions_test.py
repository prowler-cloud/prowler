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
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/workload-role"
MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"

SESSION_POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Action":["s3:GetObject"],"Resource":["*"]}]}'
)


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
        role_arns=role_arns if role_arns is not None else [ROLE_ARN],
        session_policy=session_policy,
        managed_policy_arns=managed_policy_arns or [],
    )


def _build_client(profiles):
    ra_client = mock.MagicMock()
    ra_client.profiles = profiles
    return ra_client


def _patched(ra_client):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    return [
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.rolesanywhere.rolesanywhere_profile_restricts_session_permissions.rolesanywhere_profile_restricts_session_permissions.rolesanywhere_client",
            new=ra_client,
        ),
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

    def test_unscoped_profile_fails(self):
        with _enter(_patched(_build_client({PROFILE_ARN: _profile()}))):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == PROFILE_ID
            assert result[0].resource_arn == PROFILE_ARN
            assert ROLE_ARN in result[0].status_extended

    def test_unscoped_profile_without_roles_fails_with_none_fallback(self):
        with _enter(_patched(_build_client({PROFILE_ARN: _profile(role_arns=[])}))):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "<none>" in result[0].status_extended

    def test_profile_with_session_policy_passes(self):
        with _enter(
            _patched(
                _build_client({PROFILE_ARN: _profile(session_policy=SESSION_POLICY)})
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "session policy" in result[0].status_extended

    def test_profile_with_managed_policies_passes(self):
        with _enter(
            _patched(
                _build_client(
                    {PROFILE_ARN: _profile(managed_policy_arns=[MANAGED_POLICY_ARN])}
                )
            )
        ):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_disabled_profile_passes(self):
        with _enter(_patched(_build_client({PROFILE_ARN: _profile(enabled=False)}))):
            result = _run()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "disabled" in result[0].status_extended
