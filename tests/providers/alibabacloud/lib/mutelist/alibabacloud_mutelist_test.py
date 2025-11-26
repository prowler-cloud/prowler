from unittest.mock import MagicMock

import yaml

from prowler.providers.alibabacloud.lib.mutelist.mutelist import AlibabaCloudMutelist

MUTELIST_FIXTURE_PATH = (
    "tests/providers/alibabacloud/lib/mutelist/fixtures/alibabacloud_mutelist.yaml"
)


class TestAlibabaCloudMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = AlibabaCloudMutelist(
            mutelist_path=MUTELIST_FIXTURE_PATH, account_id="1234567890"
        )

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/providers/alibabacloud/lib/mutelist/fixtures/not_present"
        mutelist = AlibabaCloudMutelist(
            mutelist_path=mutelist_path, account_id="1234567890"
        )

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_is_finding_muted(self):
        mutelist = AlibabaCloudMutelist(
            mutelist_path=MUTELIST_FIXTURE_PATH, account_id="1234567890"
        )

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "test_check"
        finding.status = "FAIL"
        finding.resource_id = "test_resource"
        finding.region = "cn-hangzhou"
        finding.resource_tags = [{"Key": "Environment", "Value": "Prod"}]

        assert mutelist.is_finding_muted(finding, account_id="1234567890")

    def test_is_finding_not_muted_with_different_resource(self):
        mutelist = AlibabaCloudMutelist(
            mutelist_path=MUTELIST_FIXTURE_PATH, account_id="1234567890"
        )

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "test_check"
        finding.status = "FAIL"
        finding.resource_id = "another_resource"
        finding.region = "cn-hangzhou"
        finding.resource_tags = [{"Key": "Environment", "Value": "Prod"}]

        assert mutelist.is_finding_muted(finding, account_id="1234567890") is False
