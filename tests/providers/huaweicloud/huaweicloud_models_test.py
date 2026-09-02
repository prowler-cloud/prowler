from unittest import mock

from huaweicloudsdkcore.auth.credentials import BasicCredentials

from prowler.providers.huaweicloud.models import (
    HuaweiCloudCredentials,
    HuaweiCloudSession,
)


class TestHuaweiCloudSessionSFSClient:
    def test_client_uses_european_sfs_turbo_endpoint(self):
        session = HuaweiCloudSession(
            credentials=HuaweiCloudCredentials(ak="test-ak", sk="test-sk"),
            region="eu-west-101",
        )

        with mock.patch.object(
            session,
            "_get_basic_credentials",
            return_value=BasicCredentials(
                ak="test-ak", sk="test-sk", project_id="test-project"
            ),
        ):
            client = session.client("sfs", "eu-west-101")

        assert client._endpoints == ["https://sfs-turbo.eu-west-101.myhuaweicloud.eu"]
