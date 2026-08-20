from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.functiongraph.functiongraph_service import (
    FunctionGraph,
)
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestFunctionGraphService:
    def test_real_session_lists_functions(self):
        regional_client = mock.MagicMock(region="eu-west-101")
        regional_client.list_functions.return_value = SimpleNamespace(
            functions=[], next_marker=None
        )
        provider = set_mocked_huaweicloud_provider()
        provider.session = SimpleNamespace(client=mock.MagicMock())
        provider.generate_regional_clients = mock.MagicMock(
            return_value={"eu-west-101": regional_client}
        )
        provider.get_default_region = mock.MagicMock(return_value="eu-west-101")

        service = FunctionGraph(provider)

        assert service.functions == []
        regional_client.list_functions.assert_called_once()

    def test_lists_every_page_and_maps_sdk_fields(self):
        first_function = SimpleNamespace(
            resource_id="resource-1",
            func_urn="urn:fss:eu-west-101:project-1:function:default:first:latest",
            func_name="first",
            runtime=None,
            timeout=None,
            memory_size=None,
            func_vpc_id=None,
        )
        second_function = SimpleNamespace(
            resource_id="resource-2",
            func_urn="urn:fss:eu-west-101:project-1:function:default:second:latest",
            func_name="second",
            runtime="Python3.9",
            timeout=30,
            memory_size=128,
            func_vpc_id="vpc-1",
        )
        regional_client = mock.MagicMock(region="eu-west-101")
        regional_client.list_functions.side_effect = [
            SimpleNamespace(functions=[first_function], next_marker=400),
            SimpleNamespace(functions=[second_function], next_marker=None),
        ]
        service = FunctionGraph.__new__(FunctionGraph)
        service.functions = []
        service.audit_resources = []
        service._call_with_retries = mock.MagicMock(
            side_effect=regional_client.list_functions.side_effect
        )

        service._list_functions(regional_client)

        assert [function.id for function in service.functions] == [
            "resource-1",
            "resource-2",
        ]
        assert service.functions[0].arn == first_function.func_urn
        assert service.functions[0].runtime == ""
        assert service.functions[0].timeout == 0
        assert service.functions[0].memory_size == 0
        assert service.functions[0].vpc_id is None
        assert service.functions[1].vpc_id == "vpc-1"
        assert service._call_with_retries.call_count == 2
        first_request = service._call_with_retries.call_args_list[0].args[1]
        second_request = service._call_with_retries.call_args_list[1].args[1]
        assert first_request.maxitems == "400"
        assert first_request.marker is None
        assert second_request.marker == "400"

    def test_api_error_does_not_fabricate_functions(self):
        function = SimpleNamespace(
            resource_id="resource-1",
            func_urn="urn:fss:eu-west-101:project-1:function:default:first:latest",
            func_name="first",
            runtime="Python3.9",
            timeout=30,
            memory_size=128,
            func_vpc_id=None,
        )
        regional_client = mock.MagicMock(region="eu-west-101")
        service = FunctionGraph.__new__(FunctionGraph)
        service.functions = []
        service.audit_resources = []
        service._call_with_retries = mock.MagicMock(
            side_effect=[
                SimpleNamespace(functions=[function], next_marker=400),
                Exception("boom"),
            ]
        )

        service._list_functions(regional_client)

        assert service.functions == []

    def test_repeated_marker_stops_pagination(self):
        function = SimpleNamespace(
            resource_id="resource-1",
            func_urn="urn:fss:eu-west-101:project-1:function:default:first:latest",
            func_name="first",
            runtime="Python3.9",
            timeout=30,
            memory_size=128,
            func_vpc_id=None,
        )
        regional_client = mock.MagicMock(region="eu-west-101")
        service = FunctionGraph.__new__(FunctionGraph)
        service.functions = []
        service.audit_resources = []
        service._call_with_retries = mock.MagicMock(
            side_effect=[
                SimpleNamespace(functions=[function], next_marker=400),
                SimpleNamespace(functions=[], next_marker=400),
            ]
        )

        service._list_functions(regional_client)

        assert [item.id for item in service.functions] == ["resource-1"]
        assert service._call_with_retries.call_count == 2
