import types


def test_validate_arguments_mutual_exclusion():
    from prowler.providers.iac.lib.arguments import arguments as iac_arguments

    Args = types.SimpleNamespace

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


def test_branch_argument():
    """Test that --branch is parsed correctly"""
    from prowler.providers.iac.lib.arguments import arguments as iac_arguments

    Args = types.SimpleNamespace

    # Branch with repository URL (valid)
    args = Args(
        scan_path=".",
        scan_repository_url="https://github.com/test/repo",
        branch="develop",
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""

    # No branch (valid)
    args = Args(
        scan_path=".",
        scan_repository_url=None,
        branch=None,
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert valid
    assert msg == ""


def test_branch_without_repository_url():
    """Test that --branch without --scan-repository-url is rejected"""
    from prowler.providers.iac.lib.arguments import arguments as iac_arguments

    Args = types.SimpleNamespace

    args = Args(
        scan_path=".",
        scan_repository_url=None,
        branch="develop",
    )
    valid, msg = iac_arguments.validate_arguments(args)
    assert not valid
    assert "--branch (-B) requires --scan-repository-url (-R)" in msg
