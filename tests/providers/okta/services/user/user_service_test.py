import json
from unittest import mock

from prowler.providers.okta.services.user.user_service import (
    ExternalDirectoryIdp,
    User,
    UserAutomation,
    _raw_rule_to_automation,
    _rule_to_automation,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _resp(headers: dict = None):
    r = mock.MagicMock()
    r.headers = headers or {}
    return r


def _fake_policy(policy_id, name="Inactivity Policy", status="ACTIVE"):
    p = mock.MagicMock()
    p.id = policy_id
    p.name = name
    p.status = status
    return p


def _fake_rule(
    rule_id="rule-1",
    name="Inactivity",
    status="ACTIVE",
    inactivity_days=35,
    inactivity_unit="DAYS",
    lifecycle_action="SUSPENDED",
    groups=None,
):
    r = mock.MagicMock()
    r.id = rule_id
    r.name = name
    r.status = status
    if inactivity_days is None:
        r.conditions.people.users.inactivity = None
    else:
        r.conditions.people.users.inactivity.number = inactivity_days
        r.conditions.people.users.inactivity.unit = inactivity_unit
    r.conditions.people.groups.include = groups or ["everyone"]
    r.actions.user_lifecycle.action = lifecycle_action
    return r


def _fake_idp(idp_type, status="ACTIVE", idp_id="0oa-1", name="x"):
    idp = mock.MagicMock()
    idp.id = idp_id
    idp.name = name
    idp.type = idp_type
    idp.status = status
    return idp


def _patch_sdk(**methods):
    return mock.patch(
        "prowler.providers.okta.lib.service.service.OktaSDKClient",
        return_value=mock.MagicMock(**methods),
    )


class Test_rule_to_automation:
    def test_parses_inactivity_and_lifecycle(self):
        rule = _fake_rule(rule_id="rule-1", name="Inactivity")
        m = _rule_to_automation(rule, "pol-1", "Inactivity Policy", "ACTIVE")
        assert isinstance(m, UserAutomation)
        assert m.id == "rule-1"
        assert m.status == "ACTIVE"
        assert m.schedule_status == "ACTIVE"
        assert m.inactivity_days == 35
        assert m.lifecycle_action == "SUSPENDED"
        assert m.applies_to_groups == ["everyone"]
        assert m.policy_id == "pol-1"
        assert m.policy_name == "Inactivity Policy"

    def test_returns_none_when_id_missing(self):
        bad = _fake_rule()
        bad.id = ""
        assert _rule_to_automation(bad, "pol", "P", "ACTIVE") is None

    def test_ignores_non_days_unit(self):
        rule = _fake_rule(inactivity_unit="WEEKS")
        m = _rule_to_automation(rule, "pol", "P", "ACTIVE")
        assert m.inactivity_days is None


class Test_User_service:
    def test_fetches_automations_via_policy_api(self):
        provider = set_mocked_okta_provider()
        policy = _fake_policy("pol-1")
        rule = _fake_rule(rule_id="rule-1")

        async def fake_list_policies(*_a, **_k):
            return ([policy], _resp({}), None)

        async def fake_list_rules(*_a, **_k):
            return ([rule], _resp({}), None)

        async def fake_list_idps(*_a, **_k):
            return ([], _resp({}), None)

        sdk = mock.MagicMock()
        sdk.list_policies = fake_list_policies
        sdk.list_policy_rules = fake_list_rules
        sdk.list_identity_providers = fake_list_idps

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk,
        ):
            service = User(provider)

        assert "rule-1" in service.automations
        assert service.automations["rule-1"].inactivity_days == 35
        assert service.external_directory_idps == {}

    def test_returns_empty_on_policies_api_error(self):
        provider = set_mocked_okta_provider()

        async def failing(*_a, **_k):
            return ([], _resp({}), Exception("E0000007"))

        async def fake_list_idps(*_a, **_k):
            return ([], _resp({}), None)

        sdk = mock.MagicMock()
        sdk.list_policies = failing
        sdk.list_identity_providers = fake_list_idps

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk,
        ):
            service = User(provider)

        assert service.automations == {}

    def test_detects_external_directory_idp(self):
        provider = set_mocked_okta_provider()

        async def empty_policies(*_a, **_k):
            return ([], _resp({}), None)

        ad = _fake_idp("ACTIVE_DIRECTORY", idp_id="0oa-ad", name="Corp AD")
        saml = _fake_idp("SAML2", idp_id="0oa-saml")

        async def fake_list_idps(*_a, **_k):
            return ([ad, saml], _resp({}), None)

        sdk = mock.MagicMock()
        sdk.list_policies = empty_policies
        sdk.list_identity_providers = fake_list_idps

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk,
        ):
            service = User(provider)

        assert "0oa-ad" in service.external_directory_idps
        assert "0oa-saml" not in service.external_directory_idps
        assert isinstance(
            service.external_directory_idps["0oa-ad"], ExternalDirectoryIdp
        )


class Test_raw_rule_to_automation:
    def test_projects_inactivity_and_lifecycle(self):
        # Real API shape: inactivity + groups live on the POLICY,
        # lifecycle action lives on the RULE under
        # `actions.updateUserLifecycle.targetStatus`.
        policy = {
            "id": "pol-1",
            "name": "TestCheck",
            "status": "ACTIVE",
            "conditions": {
                "people": {
                    "users": {"inactivity": {"number": 35, "unit": "DAYS"}},
                    "groups": {"include": ["everyone"]},
                }
            },
            "type": "USER_LIFECYCLE",
        }
        rule = {
            "id": "rule-1",
            "name": "lifecycle-rule-1",
            "status": "ACTIVE",
            "conditions": {},
            "actions": {
                "updateUserLifecycle": {
                    "targetStatus": "SUSPENDED",
                    "quietPeriod": {"number": 0, "unit": "DAYS"},
                }
            },
        }
        m = _raw_rule_to_automation(rule, policy, "pol-1", "TestCheck", "ACTIVE")
        assert isinstance(m, UserAutomation)
        assert m.id == "rule-1"
        assert m.status == "ACTIVE"
        assert m.schedule_status == "ACTIVE"
        assert m.inactivity_days == 35
        assert m.lifecycle_action == "SUSPENDED"
        assert m.applies_to_groups == ["everyone"]
        assert m.policy_id == "pol-1"
        assert m.policy_name == "TestCheck"

    def test_returns_none_when_id_missing(self):
        assert _raw_rule_to_automation({"name": "x"}, {}, "pol", "P", "ACTIVE") is None

    def test_ignores_non_days_unit(self):
        policy = {
            "id": "pol",
            "conditions": {
                "people": {"users": {"inactivity": {"number": 5, "unit": "WEEKS"}}}
            },
        }
        rule = {"id": "rule-2", "actions": {}}
        m = _raw_rule_to_automation(rule, policy, "pol", "P", "ACTIVE")
        assert m.inactivity_days is None

    def test_missing_policy_dict_gives_empty_inactivity_and_groups(self):
        rule = {
            "id": "rule-3",
            "actions": {"updateUserLifecycle": {"targetStatus": "SUSPENDED"}},
        }
        m = _raw_rule_to_automation(rule, None, "pol", "P", "ACTIVE")
        assert m.inactivity_days is None
        assert m.applies_to_groups == []
        assert m.lifecycle_action == "SUSPENDED"


class Test_User_service_sdk_discriminator_fallback:
    """Verifies the raw-JSON fallback when the SDK can't deserialize USER_LIFECYCLE.

    Okta SDK 3.4.2 ships a `Policy.from_dict` discriminator mapping that
    omits `USER_LIFECYCLE`, so the typed call raises ValueError. Without
    the fallback the whole automations list is lost; with it the raw
    JSON path projects each rule onto a `UserAutomation` snapshot.
    """

    def test_raw_fallback_projects_user_lifecycle_policy_rules(self):
        provider = set_mocked_okta_provider()

        # Real API shape: inactivity + groups on POLICY, lifecycle
        # action on RULE under `actions.updateUserLifecycle.targetStatus`.
        policy_payload = [
            {
                "id": "pol-1",
                "name": "TestCheck",
                "status": "ACTIVE",
                "type": "USER_LIFECYCLE",
                "conditions": {
                    "people": {
                        "users": {"inactivity": {"number": 35, "unit": "DAYS"}},
                        "groups": {"include": ["everyone"]},
                    }
                },
            }
        ]
        rules_payload = [
            {
                "id": "rule-1",
                "name": "lifecycle-rule-1",
                "status": "ACTIVE",
                "conditions": {},
                "actions": {
                    "updateUserLifecycle": {
                        "targetStatus": "SUSPENDED",
                        "quietPeriod": {"number": 0, "unit": "DAYS"},
                    }
                },
            }
        ]

        async def failing_list_policies(*_a, **_k):
            raise ValueError(
                "Policy failed to lookup discriminator value from {...}. "
                "Discriminator property name: type, mapping: {...}"
            )

        async def fake_list_idps(*_a, **_k):
            return ([], _resp({}), None)

        async def fake_raw_create(*_a, **kwargs):
            url = kwargs.get("url", "") or ""
            return ({"url": url}, None)

        async def fake_raw_execute(request):
            url = request.get("url", "")
            if "/api/v1/policies/pol-1/rules" in url:
                return (None, json.dumps(rules_payload), None)
            if "/api/v1/policies" in url:
                return (None, json.dumps(policy_payload), None)
            return (None, "[]", None)

        sdk = mock.MagicMock()
        sdk.list_policies = failing_list_policies
        sdk.list_identity_providers = fake_list_idps
        sdk._request_executor.create_request = fake_raw_create
        sdk._request_executor.execute = fake_raw_execute

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk,
        ):
            service = User(provider)

        assert "rule-1" in service.automations
        a = service.automations["rule-1"]
        assert a.inactivity_days == 35
        assert a.lifecycle_action == "SUSPENDED"
        assert a.schedule_status == "ACTIVE"
        assert a.policy_id == "pol-1"
        assert a.policy_name == "TestCheck"

    def test_raw_fallback_emits_shell_for_policy_with_no_rules(self):
        # Mirrors the real-world tenant state where an admin clicked
        # "Add Automation" in the UI but never configured conditions or
        # actions. The policy exists; it has zero rules. The raw fallback
        # must surface the policy as a shell UserAutomation so the check
        # FAILs with a specific message instead of dropping it.
        provider = set_mocked_okta_provider()

        async def failing_list_policies(*_a, **_k):
            raise ValueError("missing discriminator mapping")

        async def fake_list_idps(*_a, **_k):
            return ([], _resp({}), None)

        async def fake_raw_create(*_a, **kwargs):
            return ({"url": kwargs.get("url", "") or ""}, None)

        async def fake_raw_execute(request):
            url = request.get("url", "")
            if "/api/v1/policies/pol-empty/rules" in url:
                return (None, "[]", None)
            if "/api/v1/policies" in url:
                return (
                    None,
                    json.dumps(
                        [
                            {
                                "id": "pol-empty",
                                "name": "TestCheck",
                                "status": "INACTIVE",
                                "type": "USER_LIFECYCLE",
                            }
                        ]
                    ),
                    None,
                )
            return (None, "[]", None)

        sdk = mock.MagicMock()
        sdk.list_policies = failing_list_policies
        sdk.list_identity_providers = fake_list_idps
        sdk._request_executor.create_request = fake_raw_create
        sdk._request_executor.execute = fake_raw_execute

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk,
        ):
            service = User(provider)

        assert "pol-empty" in service.automations
        shell = service.automations["pol-empty"]
        assert shell.name == "TestCheck"
        assert shell.status == "INACTIVE"
        assert shell.schedule_status == "INACTIVE"
        assert shell.inactivity_days is None
        assert shell.lifecycle_action is None
        assert shell.applies_to_groups == []
        assert shell.policy_id == "pol-empty"
