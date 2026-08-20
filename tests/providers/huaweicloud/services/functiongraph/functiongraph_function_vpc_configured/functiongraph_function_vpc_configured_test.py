from unittest import mock

from prowler.lib.check.models import CheckMetadata
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_functiongraph_function_vpc_configured:
    def test_metadata_describes_vpc_attachment_accurately(self):
        metadata = CheckMetadata.parse_file(
            "prowler/providers/huaweicloud/services/functiongraph/"
            "functiongraph_function_vpc_configured/"
            "functiongraph_function_vpc_configured.metadata.json"
        )

        assert metadata.ResourceIdTemplate == ""
        assert "direct internet access" not in metadata.Risk
        assert metadata.AdditionalURLs == [
            "https://support.huaweicloud.com/intl/en-us/api-functiongraph/functiongraph_06_0111.html"
        ]
        assert metadata.Remediation.Code.Other

    def test_functiongraph_vpc_configured_pass(self):
        functiongraph_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.functiongraph.functiongraph_function_vpc_configured.functiongraph_function_vpc_configured.functiongraph_client",
                new=functiongraph_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.functiongraph.functiongraph_function_vpc_configured.functiongraph_function_vpc_configured import (
                functiongraph_function_vpc_configured,
            )
            from prowler.providers.huaweicloud.services.functiongraph.functiongraph_service import (
                FunctionGraphFunction,
            )

            functiongraph_client.functions = [
                FunctionGraphFunction(
                    id="fg-001",
                    name="function-secure",
                    arn="urn:fss:la-south-2:project:function:default:function-secure:latest",
                    runtime="Python3.9",
                    timeout=30,
                    memory_size=128,
                    vpc_id="vpc-12345",
                    region="la-south-2",
                ),
            ]
            functiongraph_client.audited_account = "123456789012"

            check = functiongraph_function_vpc_configured()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert results[0].resource_id == "fg-001"
            assert results[0].resource_name == "function-secure"
            assert results[0].resource_arn.endswith("function-secure:latest")
            assert "configured within VPC" in results[0].status_extended

    def test_functiongraph_vpc_configured_fail(self):
        functiongraph_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.functiongraph.functiongraph_function_vpc_configured.functiongraph_function_vpc_configured.functiongraph_client",
                new=functiongraph_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.functiongraph.functiongraph_function_vpc_configured.functiongraph_function_vpc_configured import (
                functiongraph_function_vpc_configured,
            )
            from prowler.providers.huaweicloud.services.functiongraph.functiongraph_service import (
                FunctionGraphFunction,
            )

            functiongraph_client.functions = [
                FunctionGraphFunction(
                    id="fg-002",
                    name="function-insecure",
                    arn="urn:fss:la-south-2:project:function:default:function-insecure:latest",
                    runtime="Python3.9",
                    timeout=30,
                    memory_size=128,
                    vpc_id=None,
                    region="la-south-2",
                ),
            ]
            functiongraph_client.audited_account = "123456789012"

            check = functiongraph_function_vpc_configured()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "fg-002"
            assert "not configured within a VPC" in results[0].status_extended

    def test_functiongraph_vpc_configured_mixed(self):
        functiongraph_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.functiongraph.functiongraph_function_vpc_configured.functiongraph_function_vpc_configured.functiongraph_client",
                new=functiongraph_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.functiongraph.functiongraph_function_vpc_configured.functiongraph_function_vpc_configured import (
                functiongraph_function_vpc_configured,
            )
            from prowler.providers.huaweicloud.services.functiongraph.functiongraph_service import (
                FunctionGraphFunction,
            )

            functiongraph_client.functions = [
                FunctionGraphFunction(
                    id="fg-001",
                    name="function-secure",
                    arn="urn:fss:la-south-2:project:function:default:function-secure:latest",
                    runtime="Python3.9",
                    timeout=30,
                    memory_size=128,
                    vpc_id="vpc-12345",
                    region="la-south-2",
                ),
                FunctionGraphFunction(
                    id="fg-002",
                    name="function-insecure",
                    arn="urn:fss:la-south-2:project:function:default:function-insecure:latest",
                    runtime="Python3.9",
                    timeout=30,
                    memory_size=128,
                    vpc_id=None,
                    region="la-south-2",
                ),
            ]
            functiongraph_client.audited_account = "123456789012"

            check = functiongraph_function_vpc_configured()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "PASS"
            assert results[1].status == "FAIL"

    def test_functiongraph_vpc_configured_empty(self):
        functiongraph_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.functiongraph.functiongraph_function_vpc_configured.functiongraph_function_vpc_configured.functiongraph_client",
                new=functiongraph_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.functiongraph.functiongraph_function_vpc_configured.functiongraph_function_vpc_configured import (
                functiongraph_function_vpc_configured,
            )

            functiongraph_client.functions = []
            functiongraph_client.audited_account = "123456789012"

            check = functiongraph_function_vpc_configured()
            results = check.execute()

            assert len(results) == 0
