from unittest.mock import MagicMock

from prowler.providers.supabase.models import (
    SupabaseIdentityInfo,
    SupabaseOrganization,
    SupabaseSession,
)

ACCESS_TOKEN = "sbp_test_token"
ORGANIZATION_ID = "org-id"
ORGANIZATION_NAME = "Test Organization"
ORGANIZATION_SLUG = "test-organization"
USER_ID = "user-id"


def set_mocked_supabase_provider():
    provider = MagicMock()
    provider.type = "supabase"
    provider.session = SupabaseSession(
        access_token=ACCESS_TOKEN,
        http_session=MagicMock(),
    )
    provider.identity = SupabaseIdentityInfo(
        organizations=[
            SupabaseOrganization(
                id=ORGANIZATION_ID,
                name=ORGANIZATION_NAME,
                slug=ORGANIZATION_SLUG,
            )
        ]
    )
    provider.audit_config = {"max_retries": 0}
    provider.fixer_config = {}
    return provider
