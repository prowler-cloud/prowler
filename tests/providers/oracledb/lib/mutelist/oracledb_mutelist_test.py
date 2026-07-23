from unittest.mock import MagicMock

import yaml

from prowler.providers.oracledb.lib.mutelist.mutelist import OracledbMutelist

MUTELIST_FIXTURE_PATH = (
    "tests/providers/oracledb/lib/mutelist/fixtures/oracledb_mutelist.yaml"
)


class TestOracledbMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = OracledbMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/providers/oracledb/lib/mutelist/fixtures/not_present"
        mutelist = OracledbMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = OracledbMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted_match(self):
        mutelist_content = {
            "Accounts": {
                "ORCL.EXAMPLE.COM": {
                    "Checks": {
                        "users_sample_schemas_removed": {
                            "Regions": ["*"],
                            "Resources": ["ORCL.EXAMPLE.COM"],
                        }
                    }
                }
            }
        }
        mutelist = OracledbMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata.CheckID = "users_sample_schemas_removed"
        finding.resource_name = "ORCL.EXAMPLE.COM"
        finding.resource_tags = []

        assert (
            mutelist.is_finding_muted(finding, database_name="ORCL.EXAMPLE.COM") is True
        )

    def test_is_finding_muted_no_match(self):
        mutelist_content = {
            "Accounts": {
                "ORCL.EXAMPLE.COM": {
                    "Checks": {
                        "users_sample_schemas_removed": {
                            "Regions": ["*"],
                            "Resources": ["ORCL.EXAMPLE.COM"],
                        }
                    }
                }
            }
        }
        mutelist = OracledbMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata.CheckID = "users_password_expiration_configured"
        finding.resource_name = "APPUSER"
        finding.resource_tags = []

        assert (
            mutelist.is_finding_muted(finding, database_name="ORCL.EXAMPLE.COM")
            is False
        )

    def test_is_finding_muted_no_match_on_different_database(self):
        mutelist_content = {
            "Accounts": {
                "ORCL.EXAMPLE.COM": {
                    "Checks": {
                        "users_sample_schemas_removed": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                        }
                    }
                }
            }
        }
        mutelist = OracledbMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata.CheckID = "users_sample_schemas_removed"
        finding.resource_name = "ORCL.EXAMPLE.COM"
        finding.resource_tags = []

        assert (
            mutelist.is_finding_muted(finding, database_name="OTHER.EXAMPLE.COM")
            is False
        )
