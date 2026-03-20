from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.vercel.lib.service.service import VercelService


class Team(VercelService):
    """Retrieve Vercel team configuration and membership."""

    def __init__(self, provider):
        super().__init__("Team", provider)
        self.teams: dict[str, VercelTeam] = {}
        self._fetch_team()

    def _fetch_team(self):
        """Fetch team details and members for all teams in scope."""
        team_ids = self._all_team_ids
        if not team_ids:
            logger.info("Team - No teams found, skipping team checks")
            return

        for team_id in team_ids:
            self._fetch_single_team(team_id)

    def _fetch_single_team(self, team_id: str):
        """Fetch details and members for a single team."""
        try:
            # Fetch team details (pass teamId explicitly for auto-discovered teams)
            team_data = self._get(f"/v2/teams/{team_id}", params={"teamId": team_id})
            if not team_data:
                return

            # Parse SAML config
            saml_config = None
            saml_raw = team_data.get("saml", {}) or {}
            if saml_raw:
                # Vercel returns saml.connection object when SAML is configured
                connection = saml_raw.get("connection", {}) or {}
                saml_config = SAMLConfig(
                    status=(
                        "enabled"
                        if connection.get("status") == "linked"
                        or saml_raw.get("status") == "enabled"
                        else "disabled"
                    ),
                    enforced=team_data.get("saml", {}).get("enforced", False)
                    or team_data.get("enabledSSOEnforcement", False),
                    provider=connection.get("type"),
                )

            # Parse directory sync
            dir_sync = False
            # Check for SCIM configuration
            if team_data.get("enabledScim") or team_data.get("scim"):
                dir_sync = True

            created_at = None
            if team_data.get("createdAt"):
                created_at = datetime.fromtimestamp(
                    team_data["createdAt"] / 1000, tz=timezone.utc
                )

            team = VercelTeam(
                id=team_data.get("id", team_id),
                name=team_data.get("name", ""),
                slug=team_data.get("slug", ""),
                saml=saml_config,
                directory_sync_enabled=dir_sync,
                created_at=created_at,
            )

            # Fetch members
            self._fetch_members(team)

            self.teams[team.id] = team
            logger.info(
                f"Team - Loaded team {team.name} with {len(team.members)} members"
            )

        except Exception as error:
            logger.error(
                f"Team - Error fetching team {team_id}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _fetch_members(self, team: "VercelTeam"):
        """Fetch all members for a team."""
        try:
            raw_members = self._paginate(
                f"/v2/teams/{team.id}/members",
                "members",
                params={"teamId": team.id},
            )

            for member in raw_members:
                joined_at = None
                if member.get("joinedFrom", {}).get("commitAt"):
                    joined_at = datetime.fromtimestamp(
                        member["joinedFrom"]["commitAt"] / 1000, tz=timezone.utc
                    )
                elif member.get("createdAt"):
                    joined_at = datetime.fromtimestamp(
                        member["createdAt"] / 1000, tz=timezone.utc
                    )

                created_at = None
                if member.get("createdAt"):
                    created_at = datetime.fromtimestamp(
                        member["createdAt"] / 1000, tz=timezone.utc
                    )

                team.members.append(
                    VercelTeamMember(
                        id=member.get("uid", member.get("id", "")),
                        email=member.get("email", ""),
                        role=member.get("role", "MEMBER"),
                        status=(
                            "invited" if member.get("confirmed") is False else "active"
                        ),
                        joined_at=joined_at,
                        created_at=created_at,
                    )
                )

        except Exception as error:
            logger.error(
                f"Team - Error fetching members for {team.name}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class SAMLConfig(BaseModel):
    status: str = "disabled"  # "enabled" | "disabled"
    enforced: bool = False
    provider: Optional[str] = None


class VercelTeamMember(BaseModel):
    id: str
    email: str
    role: str  # "OWNER" | "MEMBER" | "DEVELOPER" | "VIEWER" | "BILLING"
    status: str = "active"  # "active" | "invited"
    joined_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class VercelTeam(BaseModel):
    id: str
    name: str
    slug: str
    saml: Optional[SAMLConfig] = None
    directory_sync_enabled: bool = False
    members: list[VercelTeamMember] = Field(default_factory=list)
    created_at: Optional[datetime] = None
