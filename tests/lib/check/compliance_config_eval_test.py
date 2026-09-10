from types import SimpleNamespace
from unittest.mock import patch

import pytest

from prowler.lib.check.compliance_config_eval import (
    CONFIG_NOT_VALID_PREFIX,
    accumulate_group_status,
    accumulate_overview_status,
    apply_config_status,
    build_requirement_config_status,
    evaluate_config_constraints,
    get_effective_status,
    get_scan_audit_config,
    get_scan_provider_type,
    resolve_requirement_config_status,
)

CONSTRAINTS = [
    {
        "Check": "iam_user_accesskey_unused",
        "ConfigKey": "max_unused_access_keys_days",
        "Operator": "lte",
        "Value": 45,
    }
]


class Test_evaluate_config_constraints:
    def test_no_constraints_is_compliant(self):
        assert evaluate_config_constraints(None, {}) == (True, "")
        assert evaluate_config_constraints([], {"x": 1}) == (True, "")

    def test_config_absent_assumes_default_ok(self):
        # Key not explicitly set → default assumed adequate.
        is_ok, reason = evaluate_config_constraints(CONSTRAINTS, {})
        assert is_ok is True
        assert reason == ""

    def test_none_audit_config_is_compliant(self):
        assert evaluate_config_constraints(CONSTRAINTS, None) == (True, "")

    def test_lte_satisfied(self):
        assert evaluate_config_constraints(
            CONSTRAINTS, {"max_unused_access_keys_days": 45}
        ) == (True, "")

    def test_lte_violated(self):
        is_ok, reason = evaluate_config_constraints(
            CONSTRAINTS, {"max_unused_access_keys_days": 120}
        )
        assert is_ok is False
        # Product-facing message: names the check, the applied value, what the
        # requirement needs and how to fix it, in plain language.
        assert reason.startswith(CONFIG_NOT_VALID_PREFIX)
        assert "iam_user_accesskey_unused" in reason
        assert "max_unused_access_keys_days" in reason
        assert "set to 120" in reason
        assert "45 or lower" in reason

    def test_gte_operator(self):
        c = [{"Check": "c", "ConfigKey": "k", "Operator": "gte", "Value": 10}]
        assert evaluate_config_constraints(c, {"k": 10})[0] is True
        assert evaluate_config_constraints(c, {"k": 9})[0] is False

    def test_eq_operator(self):
        c = [{"Check": "c", "ConfigKey": "k", "Operator": "eq", "Value": "HIGH"}]
        assert evaluate_config_constraints(c, {"k": "HIGH"})[0] is True
        assert evaluate_config_constraints(c, {"k": "LOW"})[0] is False

    def test_in_operator(self):
        c = [{"Check": "c", "ConfigKey": "k", "Operator": "in", "Value": [1, 2, 3]}]
        assert evaluate_config_constraints(c, {"k": 2})[0] is True
        assert evaluate_config_constraints(c, {"k": 9})[0] is False

    def test_subset_operator_allowlist(self):
        # Allowlist config: applied list must stay within the secure baseline.
        c = [
            {
                "Check": "sqlserver_recommended_minimal_tls_version",
                "ConfigKey": "recommended_minimal_tls_versions",
                "Operator": "subset",
                "Value": ["1.2", "1.3"],
            }
        ]
        assert (
            evaluate_config_constraints(
                c, {"recommended_minimal_tls_versions": ["1.2", "1.3"]}
            )[0]
            is True
        )
        # Stricter (subset) still passes.
        assert (
            evaluate_config_constraints(
                c, {"recommended_minimal_tls_versions": ["1.3"]}
            )[0]
            is True
        )
        # Widening with a weaker value breaks it.
        is_ok, reason = evaluate_config_constraints(
            c, {"recommended_minimal_tls_versions": ["1.0", "1.2", "1.3"]}
        )
        assert is_ok is False
        assert "recommended_minimal_tls_versions" in reason

    def test_superset_operator_denylist(self):
        # Denylist config: applied list must keep covering the forbidden baseline.
        c = [
            {
                "Check": "acm_certificates_with_secure_key_algorithms",
                "ConfigKey": "insecure_key_algorithms",
                "Operator": "superset",
                "Value": ["RSA-1024", "P-192"],
            }
        ]
        assert (
            evaluate_config_constraints(
                c, {"insecure_key_algorithms": ["RSA-1024", "P-192"]}
            )[0]
            is True
        )
        # Extra forbidden values are fine.
        assert (
            evaluate_config_constraints(
                c, {"insecure_key_algorithms": ["RSA-1024", "P-192", "P-224"]}
            )[0]
            is True
        )
        # Removing a forbidden value breaks it.
        assert (
            evaluate_config_constraints(c, {"insecure_key_algorithms": ["P-192"]})[0]
            is False
        )

    def test_subset_superset_non_list_not_satisfied(self):
        sub = [{"Check": "c", "ConfigKey": "k", "Operator": "subset", "Value": ["a"]}]
        sup = [{"Check": "c", "ConfigKey": "k", "Operator": "superset", "Value": ["a"]}]
        # A scalar applied value cannot satisfy a set constraint.
        assert evaluate_config_constraints(sub, {"k": "a"})[0] is False
        assert evaluate_config_constraints(sup, {"k": "a"})[0] is False

    def test_mismatched_types_not_satisfied(self):
        assert (
            evaluate_config_constraints(
                CONSTRAINTS, {"max_unused_access_keys_days": "x"}
            )[0]
            is False
        )

    def test_multiple_constraints_first_violation_reported(self):
        constraints = [
            {"Check": "a", "ConfigKey": "k1", "Operator": "lte", "Value": 45},
            {"Check": "b", "ConfigKey": "k2", "Operator": "lte", "Value": 45},
        ]
        is_ok, reason = evaluate_config_constraints(constraints, {"k1": 45, "k2": 90})
        assert is_ok is False
        # The first violation (check "b", key "k2", applied 90) is the one reported.
        assert "k2" in reason
        assert "set to 90" in reason


class Test_provider_scoping:
    # An AWS-scoped constraint on a config key whose value is too loose.
    AWS_CONSTRAINT = [
        {
            "Check": "securityhub_enabled",
            "Provider": "aws",
            "ConfigKey": "mute_non_default_regions",
            "Operator": "eq",
            "Value": False,
        }
    ]

    def test_applies_when_provider_matches(self):
        is_ok, _ = evaluate_config_constraints(
            self.AWS_CONSTRAINT, {"mute_non_default_regions": True}, "aws"
        )
        assert is_ok is False

    def test_skipped_when_provider_differs(self):
        # Same loose value, but scanning GCP → the AWS constraint must not fire.
        is_ok, reason = evaluate_config_constraints(
            self.AWS_CONSTRAINT, {"mute_non_default_regions": True}, "gcp"
        )
        assert is_ok is True
        assert reason == ""

    def test_none_provider_type_disables_scoping(self):
        # Without a known provider every constraint is evaluated (legacy default).
        is_ok, _ = evaluate_config_constraints(
            self.AWS_CONSTRAINT, {"mute_non_default_regions": True}, None
        )
        assert is_ok is False

    def test_provider_match_is_case_insensitive(self):
        # A constraint authored as "AWS" must still scope to the "aws" scan,
        # not be silently bypassed by a casing mismatch.
        constraint = [
            {
                "Check": "securityhub_enabled",
                "Provider": "AWS",
                "ConfigKey": "mute_non_default_regions",
                "Operator": "eq",
                "Value": False,
            }
        ]
        is_ok, _ = evaluate_config_constraints(
            constraint, {"mute_non_default_regions": True}, "aws"
        )
        assert is_ok is False

    def test_untagged_constraint_applies_to_any_provider(self):
        # Single-provider frameworks omit Provider → always evaluated.
        is_ok, _ = evaluate_config_constraints(
            CONSTRAINTS, {"max_unused_access_keys_days": 120}, "aws"
        )
        assert is_ok is False


# A constraint forcing FAIL when the applied value is too loose.
REGION_CONSTRAINT = [
    {
        "Check": "securityhub_enabled",
        "ConfigKey": "mute_non_default_regions",
        "Operator": "eq",
        "Value": False,
    }
]


def _legacy_req(req_id, constraints=None):
    """Fake legacy Compliance_Requirement (``Id`` / ``ConfigRequirements``)."""
    return SimpleNamespace(Id=req_id, ConfigRequirements=constraints)


def _universal_req(req_id, constraints=None):
    """Fake UniversalComplianceRequirement (``id`` / ``config_requirements``)."""
    return SimpleNamespace(id=req_id, config_requirements=constraints)


class Test_build_requirement_config_status:
    def test_only_requirements_with_constraints_included(self):
        reqs = [_legacy_req("1", CONSTRAINTS), _legacy_req("2", None)]
        status = build_requirement_config_status(
            reqs, {"max_unused_access_keys_days": 120}
        )
        assert set(status) == {"1"}
        assert status["1"][0] is False

    def test_supports_universal_requirements(self):
        reqs = [_universal_req("u1", REGION_CONSTRAINT)]
        status = build_requirement_config_status(
            reqs, {"mute_non_default_regions": True}
        )
        assert status["u1"][0] is False

    def test_compliant_when_config_satisfied(self):
        reqs = [_legacy_req("1", CONSTRAINTS)]
        status = build_requirement_config_status(
            reqs, {"max_unused_access_keys_days": 30}
        )
        assert status["1"] == (True, "")


class Test_resolve_requirement_config_status:
    def test_memoises_by_requirement_id(self):
        cache = {}
        req = _legacy_req("1", CONSTRAINTS)
        first = resolve_requirement_config_status(
            req, {"max_unused_access_keys_days": 120}, cache
        )
        assert cache["1"] is first
        assert first[0] is False
        # A different audit_config is ignored once cached (intended for one build).
        second = resolve_requirement_config_status(req, {}, cache)
        assert second is first

    def test_requirement_without_constraints_is_ok(self):
        cache = {}
        req = _legacy_req("1", None)
        assert resolve_requirement_config_status(req, {}, cache) == (True, "")


class Test_accumulate_overview_status:
    def test_fail_wins_over_earlier_pass(self):
        p, f, m = set(), set(), set()
        accumulate_overview_status(0, "PASS", p, f, m)
        accumulate_overview_status(0, "FAIL", p, f, m)
        assert (p, f, m) == (set(), {0}, set())

    def test_pass_after_fail_does_not_double_count(self):
        p, f, m = set(), set(), set()
        accumulate_overview_status(0, "FAIL", p, f, m)
        accumulate_overview_status(0, "PASS", p, f, m)
        assert (p, f, m) == (set(), {0}, set())

    def test_pass_only(self):
        p, f, m = set(), set(), set()
        accumulate_overview_status(0, "PASS", p, f, m)
        assert (p, f, m) == ({0}, set(), set())

    def test_muted(self):
        p, f, m = set(), set(), set()
        accumulate_overview_status(0, "Muted", p, f, m)
        assert (p, f, m) == (set(), set(), {0})


class Test_accumulate_group_status:
    def test_first_status_counted(self):
        counts = {"FAIL": 0, "PASS": 0, "Muted": 0}
        seen = {}
        accumulate_group_status(0, "PASS", counts, seen)
        assert counts == {"FAIL": 0, "PASS": 1, "Muted": 0}
        assert seen == {0: "PASS"}

    def test_pass_upgraded_to_fail(self):
        counts = {"FAIL": 0, "PASS": 0, "Muted": 0}
        seen = {}
        accumulate_group_status(0, "PASS", counts, seen)
        accumulate_group_status(0, "FAIL", counts, seen)
        assert counts == {"FAIL": 1, "PASS": 0, "Muted": 0}
        assert seen == {0: "FAIL"}

    def test_fail_not_downgraded_by_later_pass(self):
        counts = {"FAIL": 0, "PASS": 0, "Muted": 0}
        seen = {}
        accumulate_group_status(0, "FAIL", counts, seen)
        accumulate_group_status(0, "PASS", counts, seen)
        assert counts == {"FAIL": 1, "PASS": 0, "Muted": 0}

    def test_same_index_not_double_counted(self):
        counts = {"FAIL": 0, "PASS": 0, "Muted": 0}
        seen = {}
        accumulate_group_status(0, "PASS", counts, seen)
        accumulate_group_status(0, "PASS", counts, seen)
        assert counts["PASS"] == 1

    def test_works_with_fail_pass_only_counts(self):
        # Level-style counts (no "Muted" key) used by CIS / split tables.
        counts = {"FAIL": 0, "PASS": 0}
        seen = {}
        accumulate_group_status(0, "PASS", counts, seen)
        accumulate_group_status(0, "FAIL", counts, seen)
        assert counts == {"FAIL": 1, "PASS": 0}

    def test_muted_on_fail_pass_only_counts_raises(self):
        # Level-style callers only ever pass PASS/FAIL (they guard on
        # ``not finding.muted``). Passing "Muted" to a Muted-less counts must
        # fail loudly rather than silently create a bogus key.
        counts = {"FAIL": 0, "PASS": 0}
        with pytest.raises(KeyError):
            accumulate_group_status(0, "Muted", counts, {})

    def test_manual_status_is_ignored_not_counted(self):
        # A MANUAL finding (from a manual, checks-less requirement) has no
        # PASS/FAIL/Muted column: it must be skipped, not raise KeyError, and
        # not appear in the tally. Regression test for the M365 CIS compliance
        # crash "KeyError: 'MANUAL'" (issue #11822).
        counts = {"FAIL": 0, "PASS": 0}
        seen = {}
        accumulate_group_status(0, "MANUAL", counts, seen)
        assert counts == {"FAIL": 0, "PASS": 0}
        assert seen == {}

    def test_manual_mixed_with_pass_and_fail(self):
        # MANUAL findings interleaved with real PASS/FAIL ones only skip
        # themselves; the PASS/FAIL tally is unaffected.
        counts = {"FAIL": 0, "PASS": 0}
        seen = {}
        accumulate_group_status(0, "MANUAL", counts, seen)
        accumulate_group_status(1, "PASS", counts, seen)
        accumulate_group_status(2, "FAIL", counts, seen)
        accumulate_group_status(3, "MANUAL", counts, seen)
        assert counts == {"FAIL": 1, "PASS": 1}

    def test_manual_ignored_on_counts_with_muted_key(self):
        # MANUAL is skipped regardless of the counts shape (e.g. the universal
        # table's PASS/FAIL/Muted buckets), never creating a "MANUAL" key.
        counts = {"FAIL": 0, "PASS": 0, "Muted": 0}
        seen = {}
        accumulate_group_status(0, "MANUAL", counts, seen)
        assert counts == {"FAIL": 0, "PASS": 0, "Muted": 0}
        assert "MANUAL" not in counts


class Test_apply_config_status:
    def test_none_config_status_keeps_finding(self):
        assert apply_config_status("PASS", "ext", None) == ("PASS", "ext")

    def test_compliant_keeps_finding(self):
        assert apply_config_status("PASS", "ext", (True, "")) == ("PASS", "ext")

    def test_invalid_config_forces_fail_and_prepends_reason(self):
        # The reason already carries the full product-facing message; it is
        # prepended verbatim to the finding's extended status.
        reason = f"{CONFIG_NOT_VALID_PREFIX} bad config"
        status, extended = apply_config_status("PASS", "ext", (False, reason))
        assert status == "FAIL"
        assert extended.startswith(CONFIG_NOT_VALID_PREFIX)
        assert reason in extended
        assert "ext" in extended


class Test_get_effective_status:
    def test_none_and_compliant_keep_status(self):
        assert get_effective_status("PASS", None) == "PASS"
        assert get_effective_status("PASS", (True, "")) == "PASS"

    def test_invalid_config_forces_fail(self):
        assert get_effective_status("PASS", (False, "reason")) == "FAIL"


class Test_get_scan_audit_config:
    def test_returns_empty_without_global_provider(self):
        # No global provider set → get_global_provider() returns None →
        # ``None.audit_config`` raises AttributeError → safe empty mapping.
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=None,
        ):
            assert get_scan_audit_config() == {}


class Test_get_scan_provider_type:
    def test_returns_empty_when_no_global_provider(self):
        # No global provider set → get_global_provider() returns None →
        # ``None.type`` raises AttributeError → scoping disabled (empty string).
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=None,
        ):
            assert get_scan_provider_type() == ""

    def test_returns_global_provider_type(self):
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=SimpleNamespace(type="aws"),
        ):
            assert get_scan_provider_type() == "aws"
