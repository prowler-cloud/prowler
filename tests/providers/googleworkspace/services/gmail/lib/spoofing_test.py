import pytest

from prowler.providers.googleworkspace.services.gmail.lib.spoofing import (
    PROTECTIVE_CONSEQUENCES,
    describe_consequence,
    is_protective,
)


class TestIsProtective:
    @pytest.mark.parametrize("consequence", sorted(PROTECTIVE_CONSEQUENCES))
    def test_actions_that_move_the_message_out_of_the_inbox(self, consequence):
        assert is_protective(consequence) is True

    @pytest.mark.parametrize(
        "consequence", ["WARNING", "NO_ACTION", None, "", "spam_folder", "UNKNOWN"]
    )
    def test_everything_else_is_not_protective(self, consequence):
        """Anything the benchmark does not accept, including unknown values"""
        assert is_protective(consequence) is False


class TestDescribeConsequence:
    @pytest.mark.parametrize(
        "consequence, expected",
        [
            (None, "uses Google's default action"),
            ("NO_ACTION", "is set to take no action"),
            ("WARNING", "show a warning"),
            ("SOMETHING_NEW", "is set to 'SOMETHING_NEW'"),
        ],
    )
    def test_renders_for_finding_messages(self, consequence, expected):
        assert expected in describe_consequence(consequence)
