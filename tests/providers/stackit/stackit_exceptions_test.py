from prowler.providers.stackit.exceptions.exceptions import (
    StackITBaseException,
    StackITInvalidTokenError,
)


class Test_StackIT_Exception_Catalog_Immutability:
    """Regression: ``StackITBaseException.__init__`` previously assigned the
    per-instance ``message`` override straight onto the class-level
    ``STACKIT_ERROR_CODES`` dict, leaking the override into every later
    exception of the same code raised in the same process.
    """

    def _default_message(self, code: int, class_name: str) -> str:
        """Read the default message directly from the unmodified catalog."""
        return StackITBaseException.STACKIT_ERROR_CODES[(code, class_name)]["message"]

    def test_message_override_does_not_mutate_class_catalog(self):
        default = self._default_message(10002, "StackITInvalidTokenError")
        StackITInvalidTokenError(message="instance-specific message")
        assert self._default_message(10002, "StackITInvalidTokenError") == default

    def test_sequential_overrides_do_not_leak(self):
        """An override on instance A must not affect instance B."""
        default = self._default_message(10002, "StackITInvalidTokenError")
        StackITInvalidTokenError(message="A")
        StackITInvalidTokenError(message="B")
        second_default = self._default_message(10002, "StackITInvalidTokenError")
        assert second_default == default
