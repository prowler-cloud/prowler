from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_ack_cluster_audit_log:
    def test_no_clusters(self):
        ack_client = mock.MagicMock
        ack_client.clusters = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ack.ack_cluster_audit_log.ack_cluster_audit_log.ack_client",
            new=ack_client,
        ):
            from prowler.providers.alibabacloud.services.ack.ack_cluster_audit_log.ack_cluster_audit_log import (
                ack_cluster_audit_log,
            )

            check = ack_cluster_audit_log()
            result = check.execute()
            assert len(result) == 0

    def test_cluster_audit_log_enabled_pass(self):
        ack_client = mock.MagicMock
        cluster_id = "c-test123"
        cluster_arn = (
            f"acs:ack:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:cluster/{cluster_id}"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ack.ack_cluster_audit_log.ack_cluster_audit_log.ack_client",
            new=ack_client,
        ):
            from prowler.providers.alibabacloud.services.ack.ack_cluster_audit_log.ack_cluster_audit_log import (
                ack_cluster_audit_log,
            )
            from prowler.providers.alibabacloud.services.ack.ack_service import (
                Cluster,
            )

            ack_client.clusters = {
                cluster_arn: Cluster(
                    cluster_id=cluster_id,
                    cluster_name="test-cluster",
                    arn=cluster_arn,
                    region=ALIBABACLOUD_REGION,
                    audit_log_enabled=True,
                )
            }
            ack_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ack_cluster_audit_log()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == cluster_id
            assert "has audit logging enabled" in result[0].status_extended

    def test_cluster_audit_log_enabled_fail(self):
        ack_client = mock.MagicMock
        cluster_id = "c-test456"
        cluster_arn = (
            f"acs:ack:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:cluster/{cluster_id}"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ack.ack_cluster_audit_log.ack_cluster_audit_log.ack_client",
            new=ack_client,
        ):
            from prowler.providers.alibabacloud.services.ack.ack_cluster_audit_log.ack_cluster_audit_log import (
                ack_cluster_audit_log,
            )
            from prowler.providers.alibabacloud.services.ack.ack_service import (
                Cluster,
            )

            ack_client.clusters = {
                cluster_arn: Cluster(
                    cluster_id=cluster_id,
                    cluster_name="test-cluster",
                    arn=cluster_arn,
                    region=ALIBABACLOUD_REGION,
                    audit_log_enabled=False,
                )
            }
            ack_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ack_cluster_audit_log()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == cluster_id
            assert "does not have audit logging enabled" in result[0].status_extended
