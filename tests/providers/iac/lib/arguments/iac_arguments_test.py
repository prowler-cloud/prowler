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


def test_validate_arguments_export_ocsf_requires_provider_uid():
    # --export-ocsf without provider_uid should fail
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        export_ocsf=True,
        provider_uid=None,
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert not valid
    assert "--provider-uid is required" in msg


def test_validate_arguments_export_ocsf_with_provider_uid_passes():
    # --export-ocsf with valid provider_uid should pass
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        export_ocsf=True,
        provider_uid="https://github.com/user/repo.git",
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""


def test_validate_arguments_no_export_ocsf_without_provider_uid_passes():
    # No --export-ocsf, no provider_uid — should pass
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        export_ocsf=False,
        provider_uid=None,
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""

    # No export_ocsf attr at all — should pass
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
