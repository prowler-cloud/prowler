from unittest.mock import MagicMock

import yaml

from prowler.providers.snowflake.lib.mutelist.mutelist import SnowflakeMutelist

MUTELIST_FIXTURE_PATH = (
    "tests/providers/snowflake/lib/mutelist/fixtures/snowflake_mutelist.yaml"
)


class Test_snowflake_mutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = SnowflakeMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/providers/snowflake/lib/mutelist/fixtures/not_present"
        mutelist = SnowflakeMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_is_finding_muted(self):
        finding = MagicMock()
        finding.check_metadata.CheckID = "users_mfa_enabled"
        finding.region = "global"
        finding.resource_id = "BREAKGLASS_ADMIN"
        finding.resource_name = "BREAKGLASS_ADMIN"
        finding.resource_tags = []

        mutelist = SnowflakeMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)
        assert mutelist.is_finding_muted(finding, "myorg-myaccount")

    def test_is_finding_not_muted_for_another_user(self):
        finding = MagicMock()
        finding.check_metadata.CheckID = "users_mfa_enabled"
        finding.region = "global"
        finding.resource_id = "ALICE"
        finding.resource_name = "ALICE"
        finding.resource_tags = []

        mutelist = SnowflakeMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)
        assert not mutelist.is_finding_muted(finding, "myorg-myaccount")
