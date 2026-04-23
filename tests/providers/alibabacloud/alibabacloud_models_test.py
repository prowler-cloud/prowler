from unittest.mock import patch

from prowler.providers.alibabacloud.models import (
    AlibabaCloudCredentials,
    AlibabaCloudSession,
)


def _build_session():
    session = AlibabaCloudSession(cred_client=object())
    session._credentials = AlibabaCloudCredentials(
        access_key_id="test-access-key-id",
        access_key_secret="test-access-key-secret",
    )
    return session


def test_securitycenter_client_uses_outside_china_endpoint():
    session = _build_session()

    with patch(
        "prowler.providers.alibabacloud.models.SasClient",
        side_effect=lambda config: config,
    ):
        config = session.client("sas", "ap-northeast-1")

    assert config.endpoint == "tds.ap-southeast-1.aliyuncs.com"


def test_securitycenter_client_uses_china_endpoint():
    session = _build_session()

    with patch(
        "prowler.providers.alibabacloud.models.SasClient",
        side_effect=lambda config: config,
    ):
        config = session.client("securitycenter", "cn-hangzhou")

    assert config.endpoint == "tds.cn-shanghai.aliyuncs.com"
