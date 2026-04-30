import pytest
from unittest.mock import patch

from moto import mock_aws


@pytest.fixture(autouse=True)
def _mock_aws_globally():
    """Activate moto's mock_aws for every test under tests/providers/aws/.

    This prevents any test from accidentally hitting real AWS endpoints,
    even if it forgets to add @mock_aws on the method. Tests that never
    call boto3 are unaffected (mock_aws is a no-op in that case).
    """
    with mock_aws():
        yield


@pytest.fixture(autouse=True)
def _detect_aws_leaks():
    """Fail the test if any HTTP request reaches a real AWS endpoint."""
    calls = []
    original_send = None

    try:
        from botocore.httpsession import URLLib3Session

        original_send = URLLib3Session.send
    except ImportError:
        yield
        return

    def tracking_send(self, request):
        url = getattr(request, "url", str(request))
        if ".amazonaws.com" in url:
            calls.append(url)
        return original_send(self, request)

    with patch.object(URLLib3Session, "send", tracking_send):
        yield

    if calls:
        pytest.fail(
            f"Test leaked {len(calls)} real AWS call(s):\n"
            + "\n".join(f"  - {url}" for url in calls[:5])
        )
