from unittest.mock import MagicMock

import yaml

from prowler.providers.vercel.lib.mutelist.mutelist import VercelMutelist

MUTELIST_FIXTURE_PATH = (
    "tests/providers/vercel/lib/mutelist/fixtures/vercel_mutelist.yaml"
)


class TestVercelMutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = VercelMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/providers/vercel/lib/mutelist/fixtures/not_present"
        mutelist = VercelMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        mutelist_path = MUTELIST_FIXTURE_PATH
        with open(mutelist_path) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = VercelMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted(self):
        mutelist_content = {
            "Accounts": {
                "team_test123": {
                    "Checks": {
                        "project_deployment_protection_enabled": {
                            "Regions": ["*"],
                            "Resources": ["prj_test789"],
                        }
                    }
                }
            }
        }

        mutelist = VercelMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "project_deployment_protection_enabled"
        finding.status = "FAIL"
        finding.resource_id = "prj_test789"
        finding.resource_name = "my-test-project"
        finding.resource_tags = []

        assert mutelist.is_finding_muted(finding, "team_test123")

    def test_is_finding_not_muted(self):
        mutelist_content = {
            "Accounts": {
                "team_test123": {
                    "Checks": {
                        "project_deployment_protection_enabled": {
                            "Regions": ["*"],
                            "Resources": ["other-project-id"],
                        }
                    }
                }
            }
        }

        mutelist = VercelMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "project_deployment_protection_enabled"
        finding.status = "FAIL"
        finding.resource_id = "prj_test789"
        finding.resource_name = "my-test-project"
        finding.resource_tags = []

        assert not mutelist.is_finding_muted(finding, "team_test123")
