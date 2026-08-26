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
        "VersioningConfiguration", {"Status": "Enabled"}
    )
    service.session.client.return_value = oss_client

    result = service._get_bucket_subresource(
        bucket, "GetBucketVersioning", "versioning"
    )

    assert result == {"Status": "Enabled"}
    service.session.client.assert_called_once_with("oss", bucket.region)
    params, request, _ = oss_client.execute.call_args.args
    assert params.action == "GetBucketVersioning"
    assert params.pathname == "/?versioning"
    assert params.method == "GET"
    assert params.style == "ROA"
    assert params.body_type == "xml"
    assert request.host_map == {"bucket": bucket.name}


def test_get_bucket_subresource_returns_empty_dict_for_empty_root():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "VersioningConfiguration", None
    )
    service.session.client.return_value = oss_client

    assert (
        service._get_bucket_subresource(bucket, "GetBucketVersioning", "versioning")
        == {}
    )


def test_get_bucket_encryption_parses_aes256_rule():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "ServerSideEncryptionRule",
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}},
    )
    service.session.client.return_value = oss_client

    service._get_bucket_encryption(bucket)

    assert bucket.encryption_algorithm == "AES256"
    assert bucket.encryption_kms_key_id == ""
    assert bucket.encryption_kms_data_algorithm == ""


def test_get_bucket_encryption_parses_kms_rule():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "ServerSideEncryptionRule",
        {
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "KMS",
                "KMSMasterKeyID": "00000000-1111-2222-3333-444444444444",
                "KMSDataEncryption": "SM4",
            }
        },
    )
    service.session.client.return_value = oss_client

    service._get_bucket_encryption(bucket)

    assert bucket.encryption_algorithm == "KMS"
    assert bucket.encryption_kms_key_id == "00000000-1111-2222-3333-444444444444"
    assert bucket.encryption_kms_data_algorithm == "SM4"


def test_get_bucket_encryption_no_rule_is_not_logged_as_error():
    from Tea.exceptions import TeaException

    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.side_effect = TeaException(
        {
            "code": "NoSuchServerSideEncryptionRule",
            "message": "No encryption rules are configured for this bucket.",
        }
    )
    service.session.client.return_value = oss_client

    with patch(
        "prowler.providers.alibabacloud.services.oss.oss_service.logger"
    ) as mock_logger:
        service._get_bucket_encryption(bucket)

    mock_logger.error.assert_not_called()
    assert bucket.encryption_algorithm == ""
    assert bucket.encryption_kms_key_id == ""


def test_get_bucket_encryption_unexpected_error_is_logged():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.side_effect = RuntimeError("boom")
    service.session.client.return_value = oss_client

    with patch(
        "prowler.providers.alibabacloud.services.oss.oss_service.logger"
    ) as mock_logger:
        service._get_bucket_encryption(bucket)

    mock_logger.error.assert_called_once()
    assert bucket.encryption_algorithm == ""


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


def test_get_bucket_versioning_parses_suspended_status():
    service = _build_oss_service()
    bucket = _build_bucket()
    oss_client = MagicMock()
    oss_client.execute.return_value = _mock_subresource_response(
        "VersioningConfiguration", {"Status": "Suspended"}
    )
    service.session.client.return_value = oss_client

    service._get_bucket_versioning(bucket)

    assert bucket.versioning_status == "Suspended"


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
