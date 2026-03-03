import types

from prowler.providers.iac.lib.arguments import arguments as iac_arguments

Args = types.SimpleNamespace


def test_validate_arguments_mutual_exclusion():
    # Only scan_path (default)
    args = Args(scan_path=".", scan_repository_url=None)
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""

    # Only scan_repository_url
    args = Args(scan_path=".", scan_repository_url="https://github.com/test/repo")
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""

    # Both set, scan_path is not default
    args = Args(
        scan_path="/some/path", scan_repository_url="https://github.com/test/repo"
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert not valid
    assert "mutually exclusive" in msg

    # Both set, scan_path is default (should allow)
    args = Args(scan_path=".", scan_repository_url="https://github.com/test/repo")
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""


def test_validate_arguments_push_to_cloud_requires_provider_uid():
    # --push-to-cloud without provider_uid should fail
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        push_to_cloud=True,
        provider_uid=None,
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert not valid
    assert "--provider-uid is required" in msg


def test_validate_arguments_push_to_cloud_with_provider_uid_passes():
    # --push-to-cloud with valid provider_uid should pass
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        push_to_cloud=True,
        provider_uid="https://github.com/user/repo.git",
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""


def test_validate_arguments_no_push_to_cloud_without_provider_uid_passes():
    # No --push-to-cloud, no provider_uid — should pass
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        push_to_cloud=False,
        provider_uid=None,
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""

    # No push_to_cloud attr at all — should pass
    args = Args(scan_path=".", scan_repository_url=None)
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""


def test_validate_arguments_provider_uid_must_be_valid_url():
    # Invalid provider_uid should fail
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        provider_uid="not-a-url",
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert not valid
    assert "valid repository URL" in msg

    # HTTPS URL without .git should pass
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        provider_uid="https://github.com/user/repo",
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""

    # HTTPS URL with .git should pass
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        provider_uid="https://github.com/user/repo.git",
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""

    # SSH URL should pass
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        provider_uid="git@github.com:user/repo.git",
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""
