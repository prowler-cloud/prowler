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
    service._bucket_inventory_lock = Lock()
    service._bucket_inventory_loaded = False
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


def test_list_buckets_userdisable_is_not_logged_as_error():
    oss = _build_oss_service()

    with (
        patch("requests.get") as get_mock,
        patch(
            "prowler.providers.alibabacloud.services.oss.oss_service.logger.error"
        ) as logger_error,
    ):
        get_mock.return_value = MagicMock(
            status_code=403,
            text="<Error><Code>UserDisable</Code><Message>UserDisable</Message></Error>",
        )
        oss._list_buckets()

    assert oss.buckets == {}
    logger_error.assert_not_called()


def test_list_buckets_inventory_is_loaded_once_across_regions():
    oss = _build_oss_service()
    other_client = MagicMock()
    other_client.region = "us-east-1"
    oss.regional_clients["us-east-1"] = other_client

    with patch("requests.get") as get_mock:
        get_mock.return_value = MagicMock(
            status_code=200, text=_fake_oss_list_response()
        )
        oss.__threading_call__(oss._list_buckets)

    assert get_mock.call_count == 1


def _build_bucket(name="prowler-test"):
    from prowler.providers.alibabacloud.services.oss.oss_service import Bucket

    return Bucket(arn=f"acs:oss::1234567890:{name}", name=name, region="ap-southeast-1")


def _mock_subresource_response(root_element, content):
    """Mimic the dict the OSS SDK execute path returns for XML bodies."""
    return {"headers": {}, "statusCode": 200, "body": {root_element: content}}


def test_get_bucket_subresource_calls_execute_and_unwraps_root():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "BucketLoggingStatus", {"LoggingEnabled": {"TargetBucket": "log-bucket"}}
    )
    service.session.client.return_value = oss_client

    result = service._get_bucket_subresource(bucket, "GetBucketLogging", "logging")

    assert result == {"LoggingEnabled": {"TargetBucket": "log-bucket"}}
    service.session.client.assert_called_once_with("oss", bucket.region)
    params, request, _ = oss_client.execute.call_args.args
    assert params.action == "GetBucketLogging"
    assert params.pathname == "/?logging"
    assert params.method == "GET"
    assert params.style == "ROA"
    assert params.body_type == "xml"
    assert request.host_map == {"bucket": bucket.name}


def test_get_bucket_subresource_returns_empty_dict_for_empty_root():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "BucketLoggingStatus", None
    )
    service.session.client.return_value = oss_client

    assert service._get_bucket_subresource(bucket, "GetBucketLogging", "logging") == {}


def test_get_bucket_logging_parses_target():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "BucketLoggingStatus",
        {"LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "logs/"}},
    )
    service.session.client.return_value = oss_client

    service._get_bucket_logging(bucket)

    assert bucket.logging_enabled is True
    assert bucket.logging_target_bucket == "log-bucket"
    assert bucket.logging_target_prefix == "logs/"


def test_get_bucket_logging_disabled_when_no_target():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "BucketLoggingStatus", None
    )
    service.session.client.return_value = oss_client

    service._get_bucket_logging(bucket)

    assert bucket.logging_enabled is False
    assert bucket.logging_target_bucket == ""


def test_get_bucket_acl_parses_grant():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "AccessControlPolicy",
        {"Owner": {"ID": "1234567890"}, "AccessControlList": {"Grant": "public-read"}},
    )
    service.session.client.return_value = oss_client

    service._get_bucket_acl(bucket)

    assert bucket.acl == "public-read"


def test_get_bucket_acl_parses_private_grant_value():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "AccessControlPolicy",
        {"Owner": {"ID": "1234567890"}, "AccessControlList": {"Grant": "private"}},
    )
    service.session.client.return_value = oss_client

    service._get_bucket_acl(bucket)

    assert bucket.acl == "private"


def test_get_bucket_acl_defaults_to_private_without_grant():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "AccessControlPolicy", {"Owner": {"ID": "1234567890"}}
    )
    service.session.client.return_value = oss_client

    service._get_bucket_acl(bucket)

    assert bucket.acl == "private"


def test_get_bucket_subresource_with_real_sdk_client_unwraps_xml_root():
    """Regression test against the SDK deserialization the helper works around.

    The generated ``get_bucket_*`` methods return empty response models for
    XML bodies (root element kept by the gateway, dropped by the models). Drive
    the real client with only the HTTP call mocked to make sure the helper still
    returns the configuration after SDK upgrades.
    """
    import io

    import darabonba.core as dara_core
    from alibabacloud_oss20190517.client import Client as OssClient
    from alibabacloud_tea_openapi import models as open_api_models

    service = _build_oss_service()
    bucket = _build_bucket()
    service.session.client.return_value = OssClient(
        open_api_models.Config(
            access_key_id="AKID",
            access_key_secret="SECRET",
            endpoint="oss-ap-southeast-1.aliyuncs.com",
            region_id="ap-southeast-1",
        )
    )
    xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<BucketLoggingStatus><LoggingEnabled>"
        b"<TargetBucket>log-bucket</TargetBucket>"
        b"<TargetPrefix>logs/</TargetPrefix>"
        b"</LoggingEnabled></BucketLoggingStatus>"
    )

    class FakeHttpResponse:
        status_code = 200
        headers = {"content-type": "application/xml"}
        body = io.BytesIO(xml)

    with patch.object(dara_core.DaraCore, "do_action", return_value=FakeHttpResponse()):
        result = service._get_bucket_subresource(bucket, "GetBucketLogging", "logging")

    assert result == {
        "LoggingEnabled": {"TargetBucket": "log-bucket", "TargetPrefix": "logs/"}
    }
