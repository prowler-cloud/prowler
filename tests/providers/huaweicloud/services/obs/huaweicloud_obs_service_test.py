from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.obs.obs_service import OBS, Bucket
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"
ACCOUNT_ID = "123456789012"


def _response(status=200, body=None, error_code=None, error_message=None):
    """Build an OBS data-plane SDK response."""
    return SimpleNamespace(
        status=status,
        body=body,
        errorCode=error_code,
        errorMessage=error_message,
    )


def _bucket(name, location=REGION):
    """Build a bucket item returned by the OBS data-plane SDK."""
    return SimpleNamespace(name=name, location=location)


def _list_body(*buckets, is_truncated=False, next_marker=None):
    """Build a paginated bucket-list response body."""
    return SimpleNamespace(
        buckets=list(buckets),
        isTruncated=is_truncated,
        nextMarker=next_marker,
    )


def _provider_with_clients(management_client, data_clients):
    """Return a provider routing management and data-plane OBS clients."""
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.identity.account_id = ACCOUNT_ID

    def client(service, region):
        if service == "obs":
            return management_client
        return data_clients[region]

    provider.session.client = mock.MagicMock(side_effect=client)
    return provider


def _private_management_client():
    """Return an OBS management client that reports private buckets."""
    client = mock.MagicMock()
    client.get_bucket_public_status.return_value = SimpleNamespace(is_public=False)
    client.get_bucket_policy_public_status.return_value = SimpleNamespace(
        is_public=False
    )
    return client


class TestOBSService:
    def test_list_buckets_discovers_encryption_and_identity(self):
        management_client = _private_management_client()
        data_client = mock.MagicMock()
        data_client.listBuckets.return_value = _response(
            body=_list_body(
                _bucket("obs-encrypted"),
                _bucket("kms-encrypted"),
                _bucket("plain"),
            )
        )
        data_client.getBucketEncryption.side_effect = [
            _response(body=SimpleNamespace(encryption="AES256", key=None)),
            _response(body=SimpleNamespace(encryption="kms", key="key-id")),
            _response(
                status=404,
                error_code="NoSuchEncryptionConfiguration",
                error_message="The encryption configuration does not exist.",
            ),
        ]

        obs = OBS(_provider_with_clients(management_client, {REGION: data_client}))

        assert len(obs.buckets) == 3
        by_name = {bucket.name: bucket for bucket in obs.buckets}
        assert by_name["obs-encrypted"].is_encrypted is True
        assert by_name["obs-encrypted"].encryption == "AES256"
        assert by_name["kms-encrypted"].is_encrypted is True
        assert by_name["kms-encrypted"].encryption == "kms"
        assert by_name["kms-encrypted"].encryption_key == "key-id"
        assert by_name["plain"].is_encrypted is False
        assert by_name["plain"].encryption == ""
        assert by_name["plain"].id == "plain"
        assert by_name["plain"].arn == (
            f"huaweicloud:obs:{REGION}:{ACCOUNT_ID}:bucket/plain"
        )
        assert by_name["plain"].is_public is False
        assert by_name["plain"].acl == "private"

    def test_list_buckets_follows_pagination(self):
        management_client = _private_management_client()
        data_client = mock.MagicMock()
        data_client.listBuckets.side_effect = [
            _response(
                body=_list_body(
                    _bucket("first"), is_truncated=True, next_marker="first"
                )
            ),
            _response(body=_list_body(_bucket("second"))),
        ]
        data_client.getBucketEncryption.return_value = _response(
            status=404,
            error_code="NoSuchEncryptionConfiguration",
        )

        obs = OBS(_provider_with_clients(management_client, {REGION: data_client}))

        assert [bucket.name for bucket in obs.buckets] == ["first", "second"]
        assert data_client.listBuckets.call_args_list == [
            mock.call(isQueryLocation=True, maxKeys=1000, marker=None),
            mock.call(isQueryLocation=True, maxKeys=1000, marker="first"),
        ]

    def test_list_buckets_falls_back_when_endpoint_rejects_pagination(self):
        management_client = _private_management_client()
        data_client = mock.MagicMock()
        data_client.listBuckets.side_effect = [
            _response(
                status=400,
                error_code="InvalidRequest",
                error_message="Provide invalid parameters",
            ),
            _response(body=_list_body(_bucket("unpaginated"))),
        ]
        data_client.getBucketEncryption.return_value = _response(
            status=404,
            error_code="NoSuchEncryptionConfiguration",
        )

        obs = OBS(_provider_with_clients(management_client, {REGION: data_client}))

        assert [bucket.name for bucket in obs.buckets] == ["unpaginated"]
        assert data_client.listBuckets.call_args_list == [
            mock.call(isQueryLocation=True, maxKeys=1000, marker=None),
            mock.call(isQueryLocation=True),
        ]

    def test_encryption_access_error_is_unknown_not_unencrypted(self):
        management_client = _private_management_client()
        data_client = mock.MagicMock()
        data_client.listBuckets.return_value = _response(
            body=_list_body(_bucket("unknown"))
        )
        data_client.getBucketEncryption.return_value = _response(
            status=403,
            error_code="AccessDenied",
            error_message="Access denied.",
        )

        obs = OBS(_provider_with_clients(management_client, {REGION: data_client}))

        assert obs.buckets[0].is_encrypted is None
        assert obs.buckets[0].encryption_error == "AccessDenied: Access denied."

    def test_public_access_errors_are_unknown_not_private(self):
        management_client = mock.MagicMock()
        management_client.get_bucket_public_status.side_effect = Exception("denied")
        management_client.get_bucket_policy_public_status.side_effect = Exception(
            "denied"
        )
        data_client = mock.MagicMock()
        data_client.listBuckets.return_value = _response(
            body=_list_body(_bucket("unknown"))
        )
        data_client.getBucketEncryption.return_value = _response(
            status=404,
            error_code="NoSuchEncryptionConfiguration",
        )

        obs = OBS(_provider_with_clients(management_client, {REGION: data_client}))

        assert obs.buckets[0].is_public is None
        assert obs.buckets[0].acl == "unknown"

    def test_list_buckets_handles_api_error(self):
        data_client = mock.MagicMock()
        data_client.listBuckets.return_value = _response(
            status=403,
            error_code="AccessDenied",
            error_message="Access denied.",
        )

        obs = OBS(
            _provider_with_clients(_private_management_client(), {REGION: data_client})
        )

        assert obs.buckets == []

    def test_list_buckets_handles_sdk_exception(self):
        data_client = mock.MagicMock()
        data_client.listBuckets.side_effect = Exception("boom")

        obs = OBS(
            _provider_with_clients(_private_management_client(), {REGION: data_client})
        )

        assert obs.buckets == []


def test_bucket_model_defaults_to_unknown_discovery_state():
    bucket = Bucket(name="bucket")

    assert bucket.is_encrypted is None
    assert bucket.is_public is None
