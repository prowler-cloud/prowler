from pydantic import BaseModel

from prowler.providers.supabase.lib.service.service import SupabaseService


class Organizations(SupabaseService):
    """Retrieve Supabase organization members."""

    def __init__(self, provider):
        super().__init__("Organizations", provider)
        self.members: dict[str, SupabaseOrganizationMember] = {}
        self._fetch_members()

    def _fetch_members(self) -> None:
        """Collect members from every organization in the authenticated scope."""
        for organization in self.provider.identity.organizations:
            members = self._get(f"/v1/organizations/{organization.slug}/members")
            for member in members:
                user_id = member["user_id"]
                resource = SupabaseOrganizationMember(
                    id=user_id,
                    name=f"member {user_id}",
                    organization_slug=organization.slug,
                    organization_name=organization.name,
                    mfa_enabled=member["mfa_enabled"],
                )
                self.members[f"{organization.slug}:{user_id}"] = resource


class SupabaseOrganizationMember(BaseModel):
    """Security-relevant Supabase organization member attributes."""

    id: str
    name: str
    organization_slug: str
    organization_name: str
    mfa_enabled: bool
