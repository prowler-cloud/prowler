from typing import Dict, List, Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService

SYSTEM_RULE_DEFAULTS: Dict[str, str] = {
    "User's password changed": "INACTIVE",
    "Government-backed attacks": "ACTIVE",
    "User suspended due to suspicious activity": "ACTIVE",
    "User granted Admin privilege": "INACTIVE",
    "Suspicious programmatic login": "ACTIVE",
    "Suspicious login": "ACTIVE",
    "Leaked password": "ACTIVE",
    "Gmail potential employee spoofing": "ACTIVE",
}


class Rules(GoogleWorkspaceService):
    """Google Workspace Rules service for auditing system-defined alert rules.

    Uses the Cloud Identity Policy API v1 to read system-defined alert rule
    configurations from the Admin Console "Rules" section.
    """

    def __init__(self, provider):
        super().__init__(provider)
        self.system_defined_alerts: List[SystemDefinedAlert] = []
        self.policies_fetched = False
        self._fetch_system_defined_alerts()

    def _fetch_system_defined_alerts(self):
        """Fetch system-defined alert rules from the Cloud Identity Policy API v1."""
        logger.info("Rules - Fetching system-defined alert rules...")

        try:
            service = self._build_service("cloudidentity", "v1")

            if not service:
                logger.error("Failed to build Cloud Identity service")
                return

            request = service.policies().list(
                pageSize=100,
                filter='setting.type.matches("rule.system_defined_alerts")',
            )
            fetch_succeeded = True
            found_rules: Dict[str, SystemDefinedAlert] = {}

            while request is not None:
                try:
                    response = request.execute()

                    for policy in response.get("policies", []):
                        if not self._is_customer_level_policy(policy):
                            continue

                        setting = policy.get("setting", {})
                        value = setting.get("value", {})
                        display_name = value.get("displayName", "")

                        if display_name not in SYSTEM_RULE_DEFAULTS:
                            continue

                        alert = self._parse_alert(value)
                        found_rules[display_name] = alert
                        logger.debug(
                            f"System-defined alert rule: {display_name} "
                            f"state={alert.state} "
                            f"has_recipients={alert.email_notifications_enabled}"
                        )

                    request = service.policies().list_next(request, response)

                except Exception as error:
                    self._handle_api_error(
                        error,
                        "fetching system-defined alert rules",
                        self.provider.identity.customer_id,
                    )
                    fetch_succeeded = False
                    break

            for rule_name, default_state in SYSTEM_RULE_DEFAULTS.items():
                if rule_name not in found_rules:
                    is_active_default = default_state == "ACTIVE"
                    found_rules[rule_name] = SystemDefinedAlert(
                        display_name=rule_name,
                        state=default_state,
                        email_notifications_enabled=is_active_default,
                        all_super_admins=is_active_default,
                    )
                    logger.debug(
                        f"System-defined alert rule (default): {rule_name} "
                        f"state={default_state}"
                    )

            self.system_defined_alerts = list(found_rules.values())
            self.policies_fetched = fetch_succeeded

            logger.info(
                f"Rules policies fetched - "
                f"{len(self.system_defined_alerts)} system-defined alert rules"
            )

        except Exception as error:
            self._handle_api_error(
                error,
                "fetching system-defined alert rules",
                self.provider.identity.customer_id,
            )
            self.policies_fetched = False

    @staticmethod
    def _parse_alert(value: dict) -> "SystemDefinedAlert":
        """Parse a single system-defined alert rule from the API response."""
        display_name = value.get("displayName", "")
        state = value.get("state", "INACTIVE")

        alert_center_action = value.get("action", {}).get("alertCenterAction", {})
        severity = alert_center_action.get("alertCenterConfig", {}).get("severity")
        recipients = alert_center_action.get("recipients", [])

        all_super_admins = any(r.get("allSuperAdmins") is True for r in recipients)

        return SystemDefinedAlert(
            display_name=display_name,
            state=state,
            severity=severity,
            email_notifications_enabled=len(recipients) > 0,
            all_super_admins=all_super_admins,
        )


class SystemDefinedAlert(BaseModel):
    """Model for a system-defined alert rule."""

    display_name: str
    state: str = "INACTIVE"
    severity: Optional[str] = None
    email_notifications_enabled: bool = False
    all_super_admins: bool = False
