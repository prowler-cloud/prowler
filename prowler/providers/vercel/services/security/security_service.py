from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.vercel.lib.service.service import VercelService


class Security(VercelService):
    """Retrieve Vercel WAF/Firewall configuration per project."""

    def __init__(self, provider):
        super().__init__("Security", provider)
        self.firewall_configs: dict[str, VercelFirewallConfig] = {}

        # We need project IDs to fetch firewall configs
        # Import project_client to get project list
        from prowler.providers.vercel.services.project.project_client import (
            project_client,
        )

        self.__threading_call__(
            self._fetch_firewall_config, list(project_client.projects.values())
        )

    def _fetch_firewall_config(self, project):
        """Fetch WAF/Firewall config for a single project."""
        try:
            data = self._read_firewall_config(project)

            if data is None:
                # Firewall config endpoint unavailable for this project/token
                self.firewall_configs[project.id] = VercelFirewallConfig(
                    project_id=project.id,
                    project_name=project.name,
                    team_id=project.team_id,
                    firewall_enabled=False,
                    managed_rulesets=None,
                    name=project.name,
                    id=project.id,
                )
                return

            fw = self._normalize_firewall_config(data)

            if not fw:
                fallback_firewall_enabled = self._fallback_firewall_enabled(project)
                self.firewall_configs[project.id] = VercelFirewallConfig(
                    project_id=project.id,
                    project_name=project.name,
                    team_id=project.team_id,
                    firewall_enabled=(
                        fallback_firewall_enabled
                        if fallback_firewall_enabled is not None
                        else False
                    ),
                    managed_rulesets=self._fallback_managed_rulesets(project),
                    name=project.name,
                    id=project.id,
                )
                return

            rules = [
                rule for rule in (fw.get("rules", []) or []) if self._is_active(rule)
            ]
            managed = self._active_managed_rulesets(
                fw.get("managedRules", fw.get("managedRulesets", fw.get("crs")))
            )
            custom_rules = []
            ip_blocking = list(fw.get("ips", []) or [])
            rate_limiting = []

            for rule in rules:
                mitigate_action = self._mitigate_action(rule)

                if self._is_rate_limiting_rule(rule, mitigate_action):
                    rate_limiting.append(rule)
                elif self._is_ip_rule(rule):
                    ip_blocking.append(rule)
                else:
                    custom_rules.append(rule)

            firewall_enabled = fw.get("firewallEnabled")
            if firewall_enabled is None:
                firewall_enabled = self._fallback_firewall_enabled(project)
            if firewall_enabled is None:
                firewall_enabled = bool(rules) or bool(ip_blocking) or bool(managed)

            if not managed:
                managed = self._fallback_managed_rulesets(project)

            self.firewall_configs[project.id] = VercelFirewallConfig(
                project_id=project.id,
                project_name=project.name,
                team_id=project.team_id,
                firewall_enabled=firewall_enabled,
                managed_rulesets=managed,
                custom_rules=custom_rules,
                ip_blocking_rules=ip_blocking,
                rate_limiting_rules=rate_limiting,
                name=project.name,
                id=project.id,
            )

            logger.debug(
                f"Security - Loaded firewall config for {project.name}: "
                f"enabled={firewall_enabled}, rules={len(rules)}"
            )

        except Exception as error:
            logger.error(
                f"Security - Error fetching firewall config for {project.name}: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _read_firewall_config(self, project):
        """Read the deployed firewall config via the documented endpoint.

        See: https://vercel.com/docs/rest-api/security/read-firewall-configuration
        """
        params = self._firewall_params(project)
        config_version = getattr(project, "firewall_config_version", None)

        endpoints = []
        if config_version:
            endpoints.append(f"/v1/security/firewall/config/{config_version}")
        endpoints.append("/v1/security/firewall/config/active")

        last_error = None
        for endpoint in endpoints:
            try:
                return self._get(endpoint, params=params)
            except Exception as error:
                last_error = error
                logger.warning(
                    f"Security - Firewall config read failed for project "
                    f"{project.id} (team={getattr(project, 'team_id', None)}) "
                    f"on {endpoint} with params={params}: "
                    f"{error.__class__.__name__}: {error}"
                )

        if last_error is not None:
            logger.debug(
                f"Security - Falling back to firewall config wrapper for "
                f"{project.id} after {last_error.__class__.__name__}: {last_error}"
            )

        return self._get("/v1/security/firewall/config", params=params)

    @staticmethod
    def _firewall_params(project) -> dict:
        """Build firewall request params, preserving team scope for team projects."""
        params = {"projectId": project.id}
        team_id = getattr(project, "team_id", None)

        if isinstance(team_id, str) and team_id:
            params["teamId"] = team_id

        return params

    @staticmethod
    def _normalize_firewall_config(data: dict) -> dict:
        """Normalize firewall responses across Vercel endpoint variants."""
        if not isinstance(data, dict):
            return {}

        if "firewallConfig" in data and isinstance(data["firewallConfig"], dict):
            return data["firewallConfig"]

        if any(key in data for key in ("active", "draft", "versions")):
            return data.get("active") or {}

        return data

    @staticmethod
    def _active_managed_rulesets(managed_rules: dict | None) -> dict:
        """Return only active managed rulesets."""
        if not isinstance(managed_rules, dict):
            return {}

        return {
            ruleset: config
            for ruleset, config in managed_rules.items()
            if not isinstance(config, dict) or config.get("active", False)
        }

    @classmethod
    def _fallback_managed_rulesets(cls, project) -> dict:
        """Return active managed rulesets from project metadata."""
        return cls._active_managed_rulesets(getattr(project, "managed_rules", None))

    @staticmethod
    def _fallback_firewall_enabled(project) -> bool | None:
        """Return firewall enabled state from project metadata when available."""
        return getattr(project, "firewall_enabled", None)

    @staticmethod
    def _mitigate_action(rule: dict) -> dict:
        """Extract the nested Vercel mitigation action payload for a rule."""
        action = rule.get("action", {})
        if not isinstance(action, dict):
            return {}

        mitigate = action.get("mitigate")
        return mitigate if isinstance(mitigate, dict) else action

    @staticmethod
    def _is_active(rule: dict) -> bool:
        """Treat missing active flags as enabled for backwards compatibility."""
        return rule.get("active", True) is not False

    @classmethod
    def _is_rate_limiting_rule(
        cls, rule: dict, mitigate_action: dict | None = None
    ) -> bool:
        """Check if a firewall rule enforces rate limiting."""
        if rule.get("rateLimit"):
            return True

        mitigate = (
            mitigate_action
            if isinstance(mitigate_action, dict)
            else cls._mitigate_action(rule)
        )
        return bool(mitigate.get("rateLimit")) or mitigate.get("action") == "rate_limit"

    @staticmethod
    def _is_ip_rule(rule: dict) -> bool:
        """Check if a rule is an IP blocking rule based on conditions."""
        conditions = rule.get("conditionGroup", [])
        for group in conditions:
            for condition in group.get("conditions", []):
                if condition.get("type") == "ip_address" or condition.get("op") in (
                    "inc",
                    "eq",
                ):
                    prop = condition.get("prop", "")
                    if "ip" in prop.lower():
                        return True
        return False


class VercelFirewallConfig(BaseModel):
    """Vercel WAF/Firewall configuration per project."""

    project_id: str
    project_name: Optional[str] = None
    team_id: Optional[str] = None
    firewall_enabled: bool = False
    managed_rulesets: Optional[dict] = None  # None means config endpoint unavailable
    custom_rules: list[dict] = Field(default_factory=list)
    ip_blocking_rules: list[dict] = Field(default_factory=list)
    rate_limiting_rules: list[dict] = Field(default_factory=list)
    # Provide name/id for CheckReportVercel
    name: str = ""
    id: str = ""
