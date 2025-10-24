from unittest.mock import patch
from prowler.providers.alibabacloud.services.sls.sls_service import SLS, Project, Logstore
from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_SLS_Service:
    def test_service(self):
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ):
            sls = SLS(set_mocked_alibabacloud_provider())

            assert sls.service == "sls"
            assert sls.account_id == ALIBABACLOUD_ACCOUNT_ID
            assert sls.region == ALIBABACLOUD_REGION
            assert len(sls.regions) > 0

    def test_project_creation(self):
        project_name = "test-project"
        region = ALIBABACLOUD_REGION
        arn = f"acs:sls:{region}:{ALIBABACLOUD_ACCOUNT_ID}:project/{project_name}"

        project = Project(
            project_name=project_name,
            arn=arn,
            region=region,
            description="Test project",
            status="Normal"
        )

        assert project.project_name == project_name
        assert project.arn == arn
        assert project.region == region
        assert project.description == "Test project"
        assert project.status == "Normal"

    def test_logstore_creation(self):
        project_name = "test-project"
        logstore_name = "test-logstore"
        region = ALIBABACLOUD_REGION
        arn = f"acs:sls:{region}:{ALIBABACLOUD_ACCOUNT_ID}:logstore/{project_name}/{logstore_name}"

        logstore = Logstore(
            logstore_name=logstore_name,
            project_name=project_name,
            arn=arn,
            region=region,
            ttl=90,
            shard_count=4,
            enable_tracking=True,
            encrypt_conf={"enable": True, "encrypt_type": "default"}
        )

        assert logstore.logstore_name == logstore_name
        assert logstore.project_name == project_name
        assert logstore.arn == arn
        assert logstore.region == region
        assert logstore.ttl == 90
        assert logstore.shard_count == 4
        assert logstore.enable_tracking is True
        assert logstore.encrypt_conf["enable"] is True

    def test_logstore_default_encrypt_conf(self):
        logstore = Logstore(
            logstore_name="test",
            project_name="test-project",
            arn="arn",
            region=ALIBABACLOUD_REGION
        )

        assert logstore.encrypt_conf == {"enable": False}
