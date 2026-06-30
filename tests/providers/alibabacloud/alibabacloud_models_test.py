from unittest.mock import patch

import pytest

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


@pytest.mark.parametrize(
    ("region", "expected_endpoint"),
    [
        ("cn-beijing", "rds.aliyuncs.com"),
        ("cn-shanghai", "rds.aliyuncs.com"),
        ("cn-heyuan", "rds.aliyuncs.com"),
        ("cn-hongkong", "rds.aliyuncs.com"),
        ("ap-northeast-1", "rds.ap-northeast-1.aliyuncs.com"),
        ("cn-guangzhou", "rds.cn-guangzhou.aliyuncs.com"),
    ],
)
def test_rds_client_uses_documented_public_endpoints(region, expected_endpoint):
    session = _build_session()

    with patch(
        "prowler.providers.alibabacloud.models.RdsClient",
        side_effect=lambda config: config,
    ):
        config = session.client("rds", region)

    assert config.endpoint == expected_endpoint
