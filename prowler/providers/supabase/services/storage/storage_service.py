from prowler.providers.supabase.lib.service.service import (
    SupabaseProjectScope,
    SupabaseService,
)


class Storage(SupabaseService):
    """Retrieve Supabase Storage buckets of every project."""

    def __init__(self, provider):
        super().__init__("Storage", provider)
        self.buckets: dict[str, SupabaseStorageBucket] = {}
        self._threading_call(self._fetch_buckets, self._list_projects())

    def _fetch_buckets(self, scope: SupabaseProjectScope) -> None:
        """Collect the buckets of a project with their visibility."""
        raw_buckets = self._get_optional(
            f"/v1/projects/{scope.project_ref}/storage/buckets", "Storage buckets"
        )
        if raw_buckets is None:
            return
        for raw in raw_buckets:
            bucket_id = raw.get("id") or raw.get("name", "")
            if not bucket_id:
                continue
            key = f"{scope.project_ref}:{bucket_id}"
            self.buckets[key] = SupabaseStorageBucket(
                **{**scope.model_dump(), "id": key, "name": raw.get("name", bucket_id)},
                bucket_id=bucket_id,
                public=bool(raw.get("public")),
            )


class SupabaseStorageBucket(SupabaseProjectScope):
    """Supabase Storage bucket and its visibility."""

    bucket_id: str
    public: bool = False
