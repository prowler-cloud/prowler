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
