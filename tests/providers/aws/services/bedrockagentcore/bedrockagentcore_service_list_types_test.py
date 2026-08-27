"""ListBrowsers and ListCodeInterpreters must be paginated once per `type` enum value.

WHY THIS FILE EXISTS. The collectors request `type=SYSTEM` and `type=CUSTOM` explicitly rather than
relying on the default, because the default omits the SYSTEM built-in. `bedrockagentcore_service_test.py`
cannot catch a regression here: its mock ignores the request kwargs and returns the same payload for any
`type`, so a collector that drops the argument entirely still passes with the same assertion
(`len(ac.browsers) == 1`). A revision of this service file did exactly that and the whole suite stayed
green, so the behaviour needs a mock that is SENSITIVE to the argument.

The mock below imitates the real API as measured at the pin (botocore 1.40.61) against a live account:

    list_browsers()                 -> the CUSTOM browsers only        (2 in the probe account)
    list_browsers(type="SYSTEM")    -> aws.browser.v1                  (the built-in)
    list_browsers(type="CUSTOM")    -> the CUSTOM browsers

AWS's own reference is self-contradictory on this point, which is why it is worth pinning: the
ListBrowsers page summary says "Lists all custom browsers in your account" while its `type` parameter
says "If not specified, all browser types are returned." The summary is what the service does.
ListCodeInterpreters says only "The type of code interpreters to list" -- it makes no claim about the
default at all -- and behaves the same way.

A collector that omits `type` therefore collects the custom resources and silently drops the built-in,
which under-reports rather than merely under-counts: the checks reading this inventory are about the
built-in tools as much as the custom ones.

NO MODULE-LEVEL STATE, DELIBERATELY. A first version captured
`make_api_call = botocore.client.BaseClient._make_api_call` at import time and recorded the requested
`type` values in a module-level dict. Both are unsafe under `pytest -n auto`: import order varies across
workers, so the captured function can be another module's active mock, and the shared dict is visible to
every test in the worker. Measured cost of getting this wrong: the bedrock module passed 187/187 on its
own and in isolation under xdist, while the WHOLE aws suite gained 12 failures. So the mock is built
per test by a factory closing over a local list, and it never falls through to the real
`_make_api_call` -- it answers every operation the service touches itself.
"""

from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

ARN_BASE = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
SYSTEM_BROWSER_ARN = f"{ARN_BASE}:browser/aws.browser.v1"
CUSTOM_BROWSER_ARN = f"{ARN_BASE}:browser/custom-browser-abc123"
SYSTEM_INTERPRETER_ARN = f"{ARN_BASE}:code-interpreter/aws.codeinterpreter.v1"
CUSTOM_INTERPRETER_ARN = f"{ARN_BASE}:code-interpreter/custom-interpreter-abc123"


def _type_sensitive_mock(requested):
    """Build a `_make_api_call` replacement that records each `type` into `requested`.

    Returns SYSTEM resources ONLY for type=SYSTEM, mirroring the measured API. Both type=CUSTOM and
    the no-argument default return the custom resources -- that default branch is the one a collector
    which forgot `type` lands on, and it is why omitting the argument loses the built-in without
    losing everything.
    """

    def _mock(self, operation_name, kwarg):
        """Answer ListBrowsers and ListCodeInterpreters differently per ``type`` argument."""
        if operation_name in ("ListBrowsers", "ListCodeInterpreters"):
            requested.setdefault(operation_name, []).append(kwarg.get("type"))

        if operation_name == "ListBrowsers":
            if kwarg.get("type") == "SYSTEM":
                return {
                    "browserSummaries": [
                        {
                            "browserArn": SYSTEM_BROWSER_ARN,
                            "browserId": "aws.browser.v1",
                            "name": "aws.browser.v1",
                        }
                    ]
                }
            return {
                "browserSummaries": [
                    {
                        "browserArn": CUSTOM_BROWSER_ARN,
                        "browserId": "custom-browser-abc123",
                        "name": "custom-browser",
                    }
                ]
            }

        if operation_name == "ListCodeInterpreters":
            if kwarg.get("type") == "SYSTEM":
                return {
                    "codeInterpreterSummaries": [
                        {
                            "codeInterpreterArn": SYSTEM_INTERPRETER_ARN,
                            "codeInterpreterId": "aws.codeinterpreter.v1",
                            "name": "aws.codeinterpreter.v1",
                        }
                    ]
                }
            return {
                "codeInterpreterSummaries": [
                    {
                        "codeInterpreterArn": CUSTOM_INTERPRETER_ARN,
                        "codeInterpreterId": "custom-interpreter-abc123",
                        "name": "custom-interpreter",
                    }
                ]
            }

        if operation_name == "GetBrowser":
            return {"networkConfiguration": {"networkMode": "PUBLIC"}}
        if operation_name == "GetCodeInterpreter":
            return {"networkConfiguration": {"networkMode": "SANDBOX"}}
        if operation_name == "GetTokenVault":
            return {"kmsConfiguration": {"keyType": "ServiceManagedKey"}}
        # Everything else the service lists is out of scope here. Answer with an empty page rather
        # than delegating to the real _make_api_call: delegation needs a module-level capture of the
        # original, which is exactly what makes this file unsafe under xdist.
        return {}

    return _mock


def _collect():
    """Run the collectors under the type-sensitive mock; return (service, requested types)."""
    from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
        BedrockAgentCore,
    )

    requested: dict[str, list] = {}
    # Build the provider BEFORE the patch. set_mocked_aws_provider makes its own calls (STS and
    # friends) and this mock answers unknown operations with {} instead of delegating, so provider
    # setup inside the patch starves and every assertion fails for the wrong reason.
    provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_type_sensitive_mock(requested)
    ):
        service = BedrockAgentCore(provider)
    return service, requested


class Test_AgentCore_List_Type_Pagination:
    """Both enum values must be requested, and both results must reach the inventory."""

    @mock_aws
    def test_browsers_include_the_system_builtin_and_the_custom_one(self):
        """Both browser types reach the inventory, so the AWS built-in is not dropped."""
        ac, _ = _collect()
        # The assertion that fails when `type` is dropped: a collector using the default gets the
        # custom browser only, so the built-in is missing and the count is 1 rather than 2.
        assert SYSTEM_BROWSER_ARN in ac.browsers, (
            "the SYSTEM built-in browser is missing -- ListBrowsers was probably called without "
            "type=SYSTEM, which returns only the custom browsers"
        )
        assert CUSTOM_BROWSER_ARN in ac.browsers
        assert len(ac.browsers) == 2

    @mock_aws
    def test_browsers_request_both_enum_values_explicitly(self):
        """``type`` is passed explicitly; relying on the default omits the SYSTEM browser."""
        _, requested = _collect()
        seen = requested.get("ListBrowsers", [])
        assert set(seen) == {"SYSTEM", "CUSTOM"}, (
            f"expected both enum values to be requested, saw {seen!r}; "
            "None means the default was relied on"
        )
        assert None not in seen

    @mock_aws
    def test_code_interpreters_include_the_system_builtin_and_the_custom_one(self):
        """Both interpreter types reach the inventory, including ``aws.codeinterpreter.v1``."""
        ac, _ = _collect()
        assert SYSTEM_INTERPRETER_ARN in ac.code_interpreters, (
            "the SYSTEM built-in code interpreter is missing -- ListCodeInterpreters was probably "
            "called without type=SYSTEM"
        )
        assert CUSTOM_INTERPRETER_ARN in ac.code_interpreters
        assert len(ac.code_interpreters) == 2

    @mock_aws
    def test_code_interpreters_request_both_enum_values_explicitly(self):
        """``type`` is passed explicitly for interpreters too, for the same measured reason."""
        _, requested = _collect()
        seen = requested.get("ListCodeInterpreters", [])
        assert set(seen) == {"SYSTEM", "CUSTOM"}, (
            f"expected both enum values to be requested, saw {seen!r}; "
            "None means the default was relied on"
        )
        assert None not in seen
