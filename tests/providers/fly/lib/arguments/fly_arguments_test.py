from argparse import Namespace

from prowler.providers.fly.lib.arguments.arguments import validate_arguments


class Test_fly_validate_arguments:
    def test_no_app_filter_is_valid(self):
        assert validate_arguments(Namespace(app=None)) == (True, "")

    def test_app_names_are_stripped(self):
        arguments = Namespace(app=[" api ", "worker"])

        assert validate_arguments(arguments) == (True, "")
        assert arguments.app == ["api", "worker"]

    def test_app_without_values_is_rejected(self):
        valid, message = validate_arguments(Namespace(app=[]))

        assert valid is False
        assert "--app/--apps requires at least one Fly.io app name" in message

    def test_app_with_only_blank_values_is_rejected(self):
        valid, message = validate_arguments(Namespace(app=["", "   "]))

        assert valid is False
        assert "--app/--apps requires at least one Fly.io app name" in message

    def test_arguments_without_app_attribute_are_valid(self):
        assert validate_arguments(Namespace()) == (True, "")
