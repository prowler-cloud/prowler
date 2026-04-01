from unittest.mock import patch

import pytest

from prowler.lib.cli.redact import (
    REDACTED_VALUE,
    get_sensitive_arguments,
    redact_argv,
    warn_sensitive_argument_values,
)


@pytest.fixture
def mock_sensitive_args():
    """Mock get_sensitive_arguments to return a known set."""
    sensitive = frozenset(
        {"--shodan", "--personal-access-token", "--atlas-private-key"}
    )
    with patch(
        "prowler.lib.cli.redact.get_sensitive_arguments", return_value=sensitive
    ):
        yield sensitive


class TestRedactArgv:
    def test_empty_argv(self, mock_sensitive_args):
        assert redact_argv([]) == ""

    def test_no_sensitive_flags(self, mock_sensitive_args):
        argv = ["aws", "--region", "eu-west-1", "--output-formats", "html"]
        assert redact_argv(argv) == "aws --region eu-west-1 --output-formats html"

    def test_sensitive_flag_with_value(self, mock_sensitive_args):
        argv = ["aws", "--shodan", "abc123"]
        assert redact_argv(argv) == f"aws --shodan {REDACTED_VALUE}"

    def test_sensitive_flag_with_equals_syntax(self, mock_sensitive_args):
        argv = ["aws", "--shodan=abc123"]
        assert redact_argv(argv) == f"aws --shodan={REDACTED_VALUE}"

    def test_sensitive_flag_at_end_without_value(self, mock_sensitive_args):
        argv = ["aws", "--shodan"]
        assert redact_argv(argv) == "aws --shodan"

    def test_sensitive_flag_followed_by_another_flag(self, mock_sensitive_args):
        argv = ["aws", "--shodan", "--region", "eu-west-1"]
        # --region starts with '-', so --shodan value is not redacted (it has no value)
        assert redact_argv(argv) == "aws --shodan --region eu-west-1"

    def test_multiple_sensitive_flags(self, mock_sensitive_args):
        argv = [
            "github",
            "--personal-access-token",
            "ghp_secret123",
            "--shodan",
            "shodan_key",
        ]
        assert (
            redact_argv(argv)
            == f"github --personal-access-token {REDACTED_VALUE} --shodan {REDACTED_VALUE}"
        )

    def test_mixed_sensitive_and_non_sensitive(self, mock_sensitive_args):
        argv = [
            "mongodbatlas",
            "--atlas-private-key",
            "my_secret",
            "--atlas-project-id",
            "proj123",
        ]
        assert (
            redact_argv(argv)
            == f"mongodbatlas --atlas-private-key {REDACTED_VALUE} --atlas-project-id proj123"
        )

    def test_sensitive_flag_equals_with_other_args(self, mock_sensitive_args):
        argv = [
            "aws",
            "--region",
            "us-east-1",
            "--shodan=key123",
            "--output-formats",
            "html",
        ]
        assert (
            redact_argv(argv)
            == f"aws --region us-east-1 --shodan={REDACTED_VALUE} --output-formats html"
        )

    def test_non_sensitive_flag_with_equals(self, mock_sensitive_args):
        argv = ["aws", "--region=us-east-1"]
        assert redact_argv(argv) == "aws --region=us-east-1"


class TestWarnSensitiveArgumentValues:
    def test_no_warning_without_sensitive_flags(self, capsys, mock_sensitive_args):
        warn_sensitive_argument_values(["aws", "--region", "eu-west-1"])
        assert capsys.readouterr().out == ""

    def test_no_warning_flag_without_value(self, capsys, mock_sensitive_args):
        warn_sensitive_argument_values(["github", "--personal-access-token"])
        assert capsys.readouterr().out == ""

    def test_no_warning_flag_followed_by_another_flag(
        self, capsys, mock_sensitive_args
    ):
        warn_sensitive_argument_values(
            ["github", "--personal-access-token", "--region", "eu-west-1"]
        )
        assert capsys.readouterr().out == ""

    def test_warning_flag_with_value(self, capsys, mock_sensitive_args):
        warn_sensitive_argument_values(
            ["github", "--personal-access-token", "ghp_secret"]
        )
        output = capsys.readouterr().out
        assert "--personal-access-token" in output
        assert "not recommended" in output

    def test_warning_flag_with_equals_syntax(self, capsys, mock_sensitive_args):
        warn_sensitive_argument_values(["aws", "--shodan=key123"])
        output = capsys.readouterr().out
        assert "--shodan" in output
        assert "not recommended" in output

    def test_warning_multiple_flags(self, capsys, mock_sensitive_args):
        warn_sensitive_argument_values(
            [
                "github",
                "--personal-access-token",
                "ghp_secret",
                "--shodan",
                "key",
            ]
        )
        output = capsys.readouterr().out
        assert "--personal-access-token" in output
        assert "--shodan" in output

    def test_no_color_output(self, capsys, mock_sensitive_args):
        warn_sensitive_argument_values(["--no-color", "aws", "--shodan", "key123"])
        output = capsys.readouterr().out
        assert "WARNING:" in output
        # Should not contain ANSI escape codes
        assert "\033[" not in output


class TestGetSensitiveArguments:
    def test_discovers_known_sensitive_arguments(self):
        """Integration test: verify the discovery mechanism finds flags from provider modules."""
        get_sensitive_arguments.cache_clear()
        result = get_sensitive_arguments()
        assert "--shodan" in result
        assert "--personal-access-token" in result
        assert "--oauth-app-token" in result
        assert "--atlas-private-key" in result
        assert "--nhn-password" in result
        assert "--os-password" in result

    def test_does_not_include_non_sensitive_flags(self):
        """Verify non-sensitive flags are not in the set."""
        get_sensitive_arguments.cache_clear()
        result = get_sensitive_arguments()
        assert "--region" not in result
        assert "--profile" not in result
        assert "--output-formats" not in result
