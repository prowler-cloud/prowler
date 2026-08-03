from unittest.mock import patch

import pytest

from prowler.providers.common.builtin import (
    builtin_check_module,
    is_builtin_check,
    is_builtin_provider,
)


class TestBuiltinCheckModule:
    def test_builds_the_sdk_module_path(self):
        assert (
            builtin_check_module("aws", "ec2", "ec2_instance_public_ip")
            == "prowler.providers.aws.services.ec2.ec2_instance_public_ip.ec2_instance_public_ip"
        )


class TestIsBuiltinProvider:
    def test_true_for_a_provider_shipped_with_the_sdk(self):
        assert is_builtin_provider("aws") is True

    def test_false_for_a_provider_that_lives_in_a_plugin(self):
        # No `prowler.providers.acme` package: find_spec raises on the absent
        # parent rather than returning None, and the helper absorbs it.
        assert is_builtin_provider("acme") is False


class TestIsBuiltinCheck:
    def test_true_for_a_check_shipped_with_the_sdk(self):
        assert is_builtin_check("aws", "ec2", "ec2_instance_public_ip") is True

    def test_false_for_an_external_check_on_a_builtin_provider(self):
        """The case that made every plug-in check unresolvable.

        `prowler.providers.aws.services.ec2` exists, so the naive probe gets
        far enough to try importing the check package as a parent — and that
        package only exists inside the plug-in. find_spec raises instead of
        returning None.
        """
        assert (
            is_builtin_check("aws", "ec2", "ec2_acme_instance_has_owner_tag") is False
        )

    def test_false_for_a_service_that_does_not_exist(self):
        assert (
            is_builtin_check("aws", "acmeservice", "acmeservice_thing_is_fine") is False
        )

    def test_false_for_an_external_provider(self):
        assert (
            is_builtin_check("acme", "inventory", "inventory_item_has_owner") is False
        )

    def test_reraises_when_a_builtin_checks_own_dependency_is_missing(self):
        """A broken import must not read as "the check is not built-in".

        Collapsing the two would turn a missing dependency into a silent
        "check not found", which is the failure mode this probe exists to
        avoid.
        """
        module = builtin_check_module("aws", "ec2", "ec2_instance_public_ip")

        with patch(
            "prowler.providers.common.builtin.importlib.util.find_spec",
            side_effect=ModuleNotFoundError("No module named 'boto3'", name="boto3"),
        ):
            with pytest.raises(ModuleNotFoundError):
                is_builtin_check("aws", "ec2", "ec2_instance_public_ip")

        # Sanity: the same error naming the check's own path is absorbed.
        with patch(
            "prowler.providers.common.builtin.importlib.util.find_spec",
            side_effect=ModuleNotFoundError(f"No module named '{module}'", name=module),
        ):
            assert is_builtin_check("aws", "ec2", "ec2_instance_public_ip") is False
