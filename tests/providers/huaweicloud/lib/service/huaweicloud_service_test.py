import pytest

from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


def _error(message="boom", error_code=None, status_code=None):
    error = Exception(message)
    if error_code is not None:
        error.error_code = error_code
    if status_code is not None:
        error.status_code = status_code
    return error


class TestHuaweiCloudServiceIsRetriableError:
    def test_retriable_by_error_code(self):
        assert HuaweiCloudService._is_retriable_error(_error(error_code="Throttling"))

    def test_retriable_by_status_code(self):
        assert HuaweiCloudService._is_retriable_error(_error(status_code=503))

    def test_retriable_by_message_substring(self):
        assert HuaweiCloudService._is_retriable_error(
            _error(message="the request timed out")
        )

    def test_non_retriable_error(self):
        assert not HuaweiCloudService._is_retriable_error(
            _error(message="AccessDenied", error_code="Forbidden", status_code=403)
        )


class TestHuaweiCloudServiceCallWithRetries:
    @staticmethod
    def _service():
        return HuaweiCloudService.__new__(HuaweiCloudService)

    def test_returns_result_on_success(self):
        service = self._service()
        assert service._call_with_retries(lambda: "ok") == "ok"

    def test_retries_once_then_succeeds(self):
        service = self._service()
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _error(error_code="Throttling")
            return "recovered"

        assert service._call_with_retries(flaky) == "recovered"
        assert calls["n"] == 2

    def test_non_retriable_error_raises_immediately(self):
        service = self._service()
        calls = {"n": 0}

        def boom():
            calls["n"] += 1
            raise _error(message="AccessDenied", status_code=403)

        with pytest.raises(Exception):
            service._call_with_retries(boom)
        assert calls["n"] == 1

    def test_exhausts_retries_and_raises(self):
        service = self._service()
        calls = {"n": 0}

        def always_throttled():
            calls["n"] += 1
            raise _error(error_code="Throttling")

        with pytest.raises(Exception):
            service._call_with_retries(always_throttled, retries=1)
        assert calls["n"] == 2
