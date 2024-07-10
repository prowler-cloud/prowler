import yaml
from mock import MagicMock

from prowler.providers.gcp.lib.mutelist.mutelist import MutelistGCP

MUTELIST_FIXTURE_PATH = "tests/providers/gcp/lib/mutelist/fixtures/gcp_mutelist.yaml"


class TestMutelistGCP:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = MutelistGCP(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/lib/mutelist/fixtures/not_present"
        mutelist = MutelistGCP(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = MutelistGCP(mutelist_content=mutelist_fixture)

        assert not mutelist.validate_mutelist()
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted(self):
        # Mutelist
        mutelist_content = {
            "Accounts": {
                "project_1": {
                    "Checks": {
                        "check_test": {
                            # TODO: review this with Sergio
                            "Regions": ["*"],
                            "Resources": ["test_resource"],
                        }
                    }
                }
            }
        }

        mutelist = MutelistGCP(mutelist_content=mutelist_content)

        finding = MagicMock
        finding.check_metadata = MagicMock
        finding.check_metadata.CheckID = "check_test"
        finding.status = "FAIL"
        finding.resource_name = "test_resource"
        finding.location = "test-location"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding, "project_1")
