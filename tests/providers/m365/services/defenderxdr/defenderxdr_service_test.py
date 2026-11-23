import asyncio
from unittest import mock

from prowler.providers.m365.services.defenderxdr.defenderxdr_service import DefenderXDR


def _service_with_response(response=None, side_effect=None):
    """Build a DefenderXDR instance without running __init__, with a mocked client."""
    service = DefenderXDR.__new__(DefenderXDR)
    post = mock.AsyncMock(return_value=response, side_effect=side_effect)
    service.client = mock.MagicMock()
    service.client.security.microsoft_graph_security_run_hunting_query.post = post
    return service


class TestRunHuntingQuery:
    def test_null_response_is_unavailable_not_empty(self):
        """A null response object must not be treated as a successful empty query."""
        service = _service_with_response(response=None)
        results, table_not_found = asyncio.run(service._run_hunting_query("query"))
        assert results is None
        assert table_not_found is False

    def test_empty_results_is_confirmed_empty(self):
        response = mock.MagicMock()
        response.results = []
        service = _service_with_response(response=response)
        results, table_not_found = asyncio.run(service._run_hunting_query("query"))
        assert results == []
        assert table_not_found is False

    def test_table_not_found_is_flagged(self):
        service = _service_with_response(
            side_effect=Exception(
                "'where' operator: Failed to resolve table or column expression named 'DeviceInfo'"
            )
        )
        results, table_not_found = asyncio.run(service._run_hunting_query("query"))
        assert results == []
        assert table_not_found is True

    def test_generic_error_is_unavailable(self):
        service = _service_with_response(side_effect=Exception("403 Forbidden"))
        results, table_not_found = asyncio.run(service._run_hunting_query("query"))
        assert results is None
        assert table_not_found is False


class TestExposedCredentials:
    def test_table_not_found_propagates_as_unavailable(self):
        """Security Exposure Management tables missing -> None (MANUAL), not [] (PASS)."""
        service = _service_with_response(
            side_effect=Exception("Failed to resolve table ExposureGraphEdges")
        )
        result = asyncio.run(service._get_exposed_credentials_privileged_users())
        assert result is None

    def test_null_response_propagates_as_unavailable(self):
        service = _service_with_response(response=None)
        result = asyncio.run(service._get_pending_cam_approvals())
        assert result is None
