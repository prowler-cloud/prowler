from typing import Optional

from pydantic import BaseModel

from tests.providers.cloudflare.cloudflare_fixtures import ZONE_ID, ZONE_NAME


class CloudflareFirewallRule(BaseModel):
    """Cloudflare firewall rule representation for testing."""

    id: Optional[str] = None
    zone_id: str
    zone_name: str
    ruleset_id: Optional[str] = None
    phase: Optional[str] = None
    action: Optional[str] = None
    expression: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True


class TestFirewallService:
    def test_cloudflare_firewall_rule_model(self):
        rule = CloudflareFirewallRule(
            id="rule-123",
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
            ruleset_id="ruleset-456",
            phase="http_ratelimit",
            action="block",
            expression="(http.request.uri.path contains '/api/')",
            description="Rate limit API requests",
            enabled=True,
        )

        assert rule.id == "rule-123"
        assert rule.zone_id == ZONE_ID
        assert rule.zone_name == ZONE_NAME
        assert rule.ruleset_id == "ruleset-456"
        assert rule.phase == "http_ratelimit"
        assert rule.action == "block"
        assert rule.expression == "(http.request.uri.path contains '/api/')"
        assert rule.description == "Rate limit API requests"
        assert rule.enabled is True

    def test_cloudflare_firewall_rule_defaults(self):
        rule = CloudflareFirewallRule(
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
        )

        assert rule.id is None
        assert rule.zone_id == ZONE_ID
        assert rule.zone_name == ZONE_NAME
        assert rule.ruleset_id is None
        assert rule.phase is None
        assert rule.action is None
        assert rule.expression is None
        assert rule.description is None
        assert rule.enabled is True

    def test_cloudflare_firewall_rule_disabled(self):
        rule = CloudflareFirewallRule(
            id="rule-disabled",
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
            phase="http_ratelimit",
            enabled=False,
        )

        assert rule.enabled is False

    def test_cloudflare_firewall_rule_custom_phase(self):
        rule = CloudflareFirewallRule(
            id="rule-custom",
            zone_id=ZONE_ID,
            zone_name=ZONE_NAME,
            phase="http_request_firewall_custom",
            action="challenge",
            expression="(cf.threat_score > 10)",
        )

        assert rule.phase == "http_request_firewall_custom"
        assert rule.action == "challenge"
