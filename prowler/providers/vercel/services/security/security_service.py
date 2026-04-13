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
            data = self._get(
                "/v1/security/firewall/config",
                params={"projectId": project.id},
            )

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

            # Parse firewall config
            fw = data.get("firewallConfig", data) if isinstance(data, dict) else {}

            # Determine if firewall is enabled
            rules = fw.get("rules", []) or []
            managed = fw.get("managedRules", fw.get("managedRulesets"))
            custom_rules = []
            ip_blocking = []
            rate_limiting = []

            for rule in rules:
                rule_action = rule.get("action", {})
                action_type = (
                    rule_action.get("type", "")
                    if isinstance(rule_action, dict)
                    else str(rule_action)
                )

                if action_type == "rate_limit" or rule.get("rateLimit"):
                    rate_limiting.append(rule)
                elif action_type in ("deny", "block") and self._is_ip_rule(rule):
                    ip_blocking.append(rule)
                else:
                    custom_rules.append(rule)

            firewall_enabled = bool(rules) or bool(managed)

            self.firewall_configs[project.id] = VercelFirewallConfig(
                project_id=project.id,
                project_name=project.name,
                team_id=project.team_id,
                firewall_enabled=firewall_enabled,
                managed_rulesets=managed if managed is not None else {},
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
