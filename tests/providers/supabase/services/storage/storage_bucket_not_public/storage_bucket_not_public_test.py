from unittest import mock

from prowler.providers.supabase.services.storage.storage_service import (
    SupabaseStorageBucket,
)
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_NAME,
    ORGANIZATION_SLUG,
    PROJECT_NAME,
    PROJECT_REF,
    PROJECT_REGION,
    set_mocked_supabase_provider,
)

CHECK_PATH = "prowler.providers.supabase.services.storage.storage_bucket_not_public.storage_bucket_not_public"


def _bucket(name, public):
    return SupabaseStorageBucket(
        id=f"{PROJECT_REF}:{name}",
        name=name,
        bucket_id=name,
        public=public,
        project_ref=PROJECT_REF,
        project_name=PROJECT_NAME,
        organization_slug=ORGANIZATION_SLUG,
        organization_name=ORGANIZATION_NAME,
        region=PROJECT_REGION,
    )


def _run(storage_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_supabase_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.storage_client", new=storage_client),
    ):
        from prowler.providers.supabase.services.storage.storage_bucket_not_public.storage_bucket_not_public import (
            storage_bucket_not_public,
        )

        return storage_bucket_not_public().execute()


class Test_storage_bucket_not_public:
    def test_no_buckets(self):
        storage_client = mock.MagicMock
        storage_client.buckets = {}

        assert len(_run(storage_client)) == 0

    def test_private_bucket_passes(self):
        storage_client = mock.MagicMock
        storage_client.buckets = {"k": _bucket("invoices", public=False)}

        result = _run(storage_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bucket invoices in project {PROJECT_NAME} is private."
        )
        assert result[0].resource_id == f"{PROJECT_REF}:invoices"
        assert result[0].resource_name == "invoices"
        assert result[0].region == PROJECT_REGION

    def test_public_bucket_fails(self):
        storage_client = mock.MagicMock
        storage_client.buckets = {"k": _bucket("avatars", public=True)}

        result = _run(storage_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bucket avatars in project {PROJECT_NAME} is public, so every object is downloadable without authentication."
        )
