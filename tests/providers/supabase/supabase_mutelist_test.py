from unittest.mock import MagicMock

import pytest

from prowler.providers.supabase.lib.mutelist.mutelist import SupabaseMutelist
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_SLUG,
    USER_ID,
)


class TestSupabaseMutelist:
    @pytest.mark.parametrize(
        ("resource_id", "expected"),
        [(USER_ID, True), ("another-user", False)],
    )
    def test_matches_organization_check_and_member(self, resource_id, expected):
        mutelist = SupabaseMutelist(
            mutelist_content={
                "Accounts": {
                    ORGANIZATION_SLUG: {
                        "Checks": {
                            "organizations_member_mfa_enabled": {
                                "Regions": ["global"],
                                "Resources": [USER_ID],
                            }
                        }
                    }
                }
            }
        )
        finding = MagicMock(
            organization_slug=ORGANIZATION_SLUG,
            resource_id=resource_id,
            resource_name=f"member {resource_id}",
            resource_tags=[],
        )
        finding.check_metadata.CheckID = "organizations_member_mfa_enabled"

        assert mutelist.is_finding_muted(finding) is expected
