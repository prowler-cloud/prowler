from unittest.mock import MagicMock

from prowler.providers.stackit.lib.mutelist.mutelist import StackITMutelist


class TestStackITMutelist:
    def test_is_finding_muted_uses_project_id_as_account(self):
        mutelist_content = {
            "Accounts": {
                "project_1": {
                    "Checks": {
                        "check_test": {
                            "Regions": ["*"],
                            "Resources": ["test_resource"],
                        }
                    }
                }
            }
        }

        mutelist = StackITMutelist(mutelist_content=mutelist_content)

        finding = MagicMock()
        finding.project_id = "project_1"
        finding.resource_id = "resource_1"
        finding.check_metadata = MagicMock()
        finding.check_metadata.CheckID = "check_test"
        finding.status = "FAIL"
        finding.resource_name = "test_resource"
        finding.location = "eu01"
        finding.resource_tags = {}

        assert mutelist.is_finding_muted(finding=finding)
