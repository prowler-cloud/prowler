from unittest.mock import MagicMock

import yaml

from prowler.providers.linode.lib.mutelist.mutelist import LinodeMutelist

MUTELIST_FIXTURE_PATH = (
    "tests/providers/linode/lib/mutelist/fixtures/linode_mutelist.yaml"
)


class Test_linode_mutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = LinodeMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/providers/linode/lib/mutelist/fixtures/not_present"
        mutelist = LinodeMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = LinodeMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted(self):
        mutelist_content = {
            "Accounts": {
                "E1AF1B6C-1111-2222-3333-444455556666": {
                    "Checks": {
                        "account_user_2fa_enabled": {
                            "Regions": ["*"],
                            "Resources": ["admin"],
                        }
                    }
                }
            }
        }

        mutelist = LinodeMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "account_user_2fa_enabled"
        finding.status = "FAIL"
        finding.region = "global"
        finding.resource_id = "admin"
        finding.resource_name = "admin"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(
            finding, "E1AF1B6C-1111-2222-3333-444455556666"
        )

    def test_is_finding_not_muted(self):
        mutelist_content = {
            "Accounts": {
                "E1AF1B6C-1111-2222-3333-444455556666": {
                    "Checks": {
                        "account_user_2fa_enabled": {
                            "Regions": ["*"],
                            "Resources": ["other-user"],
                        }
                    }
                }
            }
        }

        mutelist = LinodeMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "account_user_2fa_enabled"
        finding.status = "FAIL"
        finding.region = "global"
        finding.resource_id = "admin"
        finding.resource_name = "admin"
        finding.resource_tags = []

        assert not mutelist.is_finding_muted(
            finding, "E1AF1B6C-1111-2222-3333-444455556666"
        )
