from unittest.mock import MagicMock

import yaml

from prowler.providers.fly.lib.mutelist.mutelist import FlyMutelist
from tests.providers.fly.fly_fixtures import (
    APP_ID,
    APP_NAME,
    MACHINE_ID,
    ORG_SLUG,
    REGION,
)

MUTELIST_FIXTURE_PATH = "tests/providers/fly/lib/mutelist/fixtures/fly_mutelist.yaml"


def _finding(check_id: str, region: str, resource_id: str, resource_name: str):
    finding = MagicMock()
    finding.check_metadata = MagicMock()
    finding.check_metadata.CheckID = check_id
    finding.status = "FAIL"
    finding.region = region
    finding.resource_id = resource_id
    finding.resource_name = resource_name
    finding.resource_tags = []
    return finding


class Test_fly_mutelist:
    def test_get_mutelist_file_from_local_file(self):
        mutelist = FlyMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        assert mutelist.mutelist == mutelist_fixture
        assert mutelist.mutelist_file_path == MUTELIST_FIXTURE_PATH

    def test_get_mutelist_file_from_local_file_non_existent(self):
        mutelist_path = "tests/providers/fly/lib/mutelist/fixtures/not_present"
        mutelist = FlyMutelist(mutelist_path=mutelist_path)

        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path == mutelist_path

    def test_validate_mutelist_not_valid_key(self):
        with open(MUTELIST_FIXTURE_PATH) as f:
            mutelist_fixture = yaml.safe_load(f)["Mutelist"]

        mutelist_fixture["Accounts1"] = mutelist_fixture["Accounts"]
        del mutelist_fixture["Accounts"]

        mutelist = FlyMutelist(mutelist_content=mutelist_fixture)

        assert len(mutelist.validate_mutelist(mutelist_fixture)) == 0
        assert mutelist.mutelist == {}
        assert mutelist.mutelist_file_path is None

    def test_is_finding_muted_by_organization_and_resource_id(self):
        mutelist = FlyMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        finding = _finding("app_no_public_ip_address", "global", APP_ID, APP_NAME)

        assert mutelist.is_finding_muted(finding, ORG_SLUG)

    def test_is_finding_not_muted_for_other_organization(self):
        mutelist = FlyMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        finding = _finding("app_no_public_ip_address", "global", APP_ID, APP_NAME)

        assert not mutelist.is_finding_muted(finding, "another-org")

    def test_is_finding_not_muted_for_other_resource(self):
        mutelist = FlyMutelist(mutelist_path=MUTELIST_FIXTURE_PATH)

        finding = _finding("app_no_public_ip_address", "global", "app_other", "other")

        assert not mutelist.is_finding_muted(finding, ORG_SLUG)

    def test_is_finding_muted_by_region(self):
        mutelist_content = {
            "Accounts": {
                ORG_SLUG: {
                    "Checks": {
                        "machine_no_public_non_http_ports": {
                            "Regions": [REGION],
                            "Resources": [MACHINE_ID],
                        }
                    }
                }
            }
        }
        mutelist = FlyMutelist(mutelist_content=mutelist_content)

        muted = _finding(
            "machine_no_public_non_http_ports", REGION, MACHINE_ID, "test-machine"
        )
        other_region = _finding(
            "machine_no_public_non_http_ports", "ams", MACHINE_ID, "test-machine"
        )

        assert mutelist.is_finding_muted(muted, ORG_SLUG)
        assert not mutelist.is_finding_muted(other_region, ORG_SLUG)

    def test_resource_name_is_used_without_resource_id(self):
        mutelist_content = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "volume_encrypted_at_rest": {
                            "Regions": ["*"],
                            "Resources": ["scratch.*"],
                        }
                    }
                }
            }
        }
        mutelist = FlyMutelist(mutelist_content=mutelist_content)

        finding = _finding("volume_encrypted_at_rest", REGION, "", "scratch_volume")

        assert mutelist.is_finding_muted(finding, ORG_SLUG)
