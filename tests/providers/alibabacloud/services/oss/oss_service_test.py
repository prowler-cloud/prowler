from datetime import timezone
from threading import Lock
from unittest.mock import MagicMock, patch

from prowler.providers.alibabacloud.services.oss.oss_service import OSS


class _DummyCreds:
    def __init__(self):
        self.access_key_id = "AKID"
        self.access_key_secret = "SECRET"
        self.security_token = None


def _build_oss_service(audit_resources=None):
    """Create an OSS service instance without running __init__."""
    service = OSS.__new__(OSS)
    service.audit_resources = audit_resources or []
    service.region = "cn-hangzhou"
    service.audited_account = "1234567890"
    service.buckets = {}
    service._buckets_lock = Lock()
    client = MagicMock()
    client.region = "ap-southeast-1"
    service.regional_clients = {"ap-southeast-1": client}
    service.client = client
    service.session = MagicMock()
    service.session.get_credentials.return_value = _DummyCreds()
    # Avoid real thread pool in tests
    service.__threading_call__ = lambda call, iterator=None: [
        call(item) for item in ((iterator or service.regional_clients.values()))
    ]
    return service


def _fake_oss_list_response(bucket_name="prowler-test", location="oss-ap-southeast-1"):
    return f"""
    <ListAllMyBucketsResult>
      <Buckets>
        <Bucket>
          <Name>{bucket_name}</Name>
          <CreationDate>2025-11-26T10:26:46.000Z</CreationDate>
          <Location>{location}</Location>
        </Bucket>
      </Buckets>
    </ListAllMyBucketsResult>
    """.strip()


def test_list_buckets_parses_and_normalizes_location():
    oss = _build_oss_service()

    with patch("requests.get") as get_mock:
        get_mock.return_value = MagicMock(
            status_code=200, text=_fake_oss_list_response()
        )
        oss._list_buckets()

    arn = "acs:oss::1234567890:prowler-test"
    assert arn in oss.buckets
    stored_bucket = oss.buckets[arn]
    assert stored_bucket.region == "ap-southeast-1"
    assert stored_bucket.creation_date.tzinfo == timezone.utc


def test_list_buckets_respects_audit_filters():
    oss = _build_oss_service(audit_resources=["acs:oss::1234567890:allowed-bucket"])

    with patch("requests.get") as get_mock:
        get_mock.return_value = MagicMock(
            status_code=200,
            text=_fake_oss_list_response(bucket_name="denied-bucket"),
        )
        oss._list_buckets()

    assert list(oss.buckets.keys()) == []


def test_list_buckets_rejects_xxe_payload():
    oss = _build_oss_service()
    xxe_payload = """<?xml version="1.0"?>
    <!DOCTYPE data [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <ListAllMyBucketsResult>
      <Buckets>
        <Bucket>
          <Name>&xxe;</Name>
          <CreationDate>2025-01-01T00:00:00.000Z</CreationDate>
          <Location>oss-cn-hangzhou</Location>
        </Bucket>
      </Buckets>
    </ListAllMyBucketsResult>"""

    with patch("requests.get") as get_mock:
        get_mock.return_value = MagicMock(status_code=200, text=xxe_payload)
        oss._list_buckets()

    assert oss.buckets == {}
