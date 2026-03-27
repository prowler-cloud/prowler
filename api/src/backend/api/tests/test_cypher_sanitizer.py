"""Unit tests for the Cypher sanitizer (validation + provider-label injection)."""

from unittest.mock import patch

import pytest

from rest_framework.exceptions import ValidationError

from api.attack_paths.cypher_sanitizer import (
    inject_provider_label,
    validate_custom_query,
)

PROVIDER_ID = "019c41ee-7df3-7dec-a684-d839f95619f8"
LABEL = "_Provider_019c41ee7df37deca684d839f95619f8"


def _inject(cypher: str) -> str:
    """Shortcut that patches `get_provider_label` to avoid config imports."""
    with patch(
        "api.attack_paths.cypher_sanitizer.get_provider_label", return_value=LABEL
    ):
        return inject_provider_label(cypher, PROVIDER_ID)


# ---------------------------------------------------------------------------
# Pass A - Labeled node patterns (all clauses)
# ---------------------------------------------------------------------------


class TestLabeledNodes:
    def test_single_label(self):
        result = _inject("MATCH (n:AWSRole) RETURN n")
        assert f"(n:AWSRole:{LABEL})" in result

    def test_label_with_properties(self):
        result = _inject("MATCH (n:AWSRole {name: 'admin'}) RETURN n")
        assert f"(n:AWSRole:{LABEL} {{name: 'admin'}})" in result

    def test_multiple_labels(self):
        result = _inject("MATCH (n:AWSRole:AWSPrincipal) RETURN n")
        assert f"(n:AWSRole:AWSPrincipal:{LABEL})" in result

    def test_anonymous_labeled(self):
        result = _inject(
            "MATCH (:AWSPrincipal {arn: 'ecs-tasks.amazonaws.com'}) RETURN 1"
        )
        assert f"(:AWSPrincipal:{LABEL} {{arn: 'ecs-tasks.amazonaws.com'}})" in result

    def test_backtick_label(self):
        result = _inject("MATCH (n:`My Label`) RETURN n")
        assert f"(n:`My Label`:{LABEL})" in result

    def test_labeled_in_where_clause(self):
        """Labeled nodes in WHERE (pattern existence) still get the label."""
        result = _inject(
            "MATCH (n:AWSRole) WHERE EXISTS((n)-[:REL]->(:Target)) RETURN n"
        )
        assert f"(n:AWSRole:{LABEL})" in result
        assert f"(:Target:{LABEL})" in result

    def test_labeled_in_return_clause(self):
        """Labeled nodes in RETURN still get the label (they're always node patterns)."""
        result = _inject("MATCH (n:AWSRole) RETURN (n:AWSRole)")
        assert result.count(f":AWSRole:{LABEL}") == 2

    def test_labeled_in_optional_match(self):
        result = _inject(
            "OPTIONAL MATCH (pf:ProwlerFinding {status: 'FAIL'}) RETURN pf"
        )
        assert f"(pf:ProwlerFinding:{LABEL} {{status: 'FAIL'}})" in result


# ---------------------------------------------------------------------------
# Pass B - Bare node patterns (MATCH/OPTIONAL MATCH only)
# ---------------------------------------------------------------------------


class TestBareNodes:
    def test_bare_in_match(self):
        result = _inject("MATCH (a)-[:HAS_POLICY]->(b) RETURN a, b")
        assert f"(a:{LABEL})" in result
        assert f"(b:{LABEL})" in result

    def test_bare_with_properties_in_match(self):
        result = _inject("MATCH (n {name: 'x'}) RETURN n")
        assert f"(n:{LABEL} {{name: 'x'}})" in result

    def test_bare_in_optional_match(self):
        result = _inject("OPTIONAL MATCH (n)-[r]-(m) RETURN n")
        assert f"(n:{LABEL})" in result
        assert f"(m:{LABEL})" in result

    def test_bare_not_injected_in_return(self):
        """Bare (identifier) in RETURN could be expression grouping."""
        cypher = "MATCH (n:AWSRole) RETURN (n)"
        result = _inject(cypher)
        # The labeled (n:AWSRole) gets the label, but the bare (n) in RETURN should not
        assert f"(n:AWSRole:{LABEL})" in result
        # Count how many times the label appears - should be 1 (from MATCH only)
        assert result.count(LABEL) == 1

    def test_bare_not_injected_in_where(self):
        cypher = "MATCH (n:AWSRole) WHERE (n.x > 1) RETURN n"
        result = _inject(cypher)
        # (n.x > 1) is an expression group, not a node pattern - should be untouched
        assert "(n.x > 1)" in result

    def test_bare_not_injected_in_with(self):
        cypher = "MATCH (n:AWSRole) WITH (n) RETURN n"
        result = _inject(cypher)
        assert result.count(LABEL) == 1

    def test_bare_not_injected_in_unwind(self):
        cypher = "UNWIND nodes(path) as n OPTIONAL MATCH (n)-[r]-(m) RETURN n"
        result = _inject(cypher)
        # (n) and (m) in OPTIONAL MATCH get injected, but nodes(path) in UNWIND does not
        assert f"(n:{LABEL})" in result
        assert f"(m:{LABEL})" in result


# ---------------------------------------------------------------------------
# Function call exclusion
# ---------------------------------------------------------------------------


class TestFunctionCallExclusion:
    @pytest.mark.parametrize(
        "func_call",
        [
            "collect(DISTINCT pf)",
            "any(x IN stmt.action WHERE toLower(x) = 'iam:*')",
            "toLower(action)",
            "nodes(path)",
            "count(n)",
            "apoc.create.vNode(labels)",
            "EXISTS(n.prop)",
            "size(n.list)",
        ],
    )
    def test_function_calls_not_injected(self, func_call):
        cypher = f"MATCH (n:AWSRole) WHERE {func_call} RETURN n"
        result = _inject(cypher)
        # The function call should remain unchanged
        assert func_call in result
        # Only the MATCH labeled node should get the label
        assert result.count(LABEL) == 1


# ---------------------------------------------------------------------------
# String and comment protection
# ---------------------------------------------------------------------------


class TestProtection:
    def test_string_with_fake_node_pattern(self):
        cypher = "MATCH (n:AWSRole) WHERE n.name = '(fake:Label)' RETURN n"
        result = _inject(cypher)
        assert "'(fake:Label)'" in result
        assert result.count(LABEL) == 1

    def test_double_quoted_string(self):
        cypher = 'MATCH (n:AWSRole) WHERE n.name = "(fake:Label)" RETURN n'
        result = _inject(cypher)
        assert '"(fake:Label)"' in result
        assert result.count(LABEL) == 1

    def test_line_comment_with_node_pattern(self):
        cypher = "// (n:Fake)\nMATCH (n:AWSRole) RETURN n"
        result = _inject(cypher)
        assert "// (n:Fake)" in result
        assert result.count(LABEL) == 1

    def test_string_containing_double_slash(self):
        """Strings with // inside should be consumed as strings, not comments."""
        cypher = "MATCH (n:AWSRole {url: 'https://example.com'}) RETURN n"
        result = _inject(cypher)
        assert "'https://example.com'" in result
        assert f"(n:AWSRole:{LABEL}" in result

    def test_escaped_quotes_in_string(self):
        cypher = r"MATCH (n:AWSRole) WHERE n.name = 'it\'s a test' RETURN n"
        result = _inject(cypher)
        assert result.count(LABEL) == 1


# ---------------------------------------------------------------------------
# Clause splitting
# ---------------------------------------------------------------------------


class TestClauseSplitting:
    def test_case_insensitive_keywords(self):
        cypher = "match (n:AWSRole) where n.x = 1 return n"
        result = _inject(cypher)
        assert f"(n:AWSRole:{LABEL})" in result

    def test_optional_match_with_extra_whitespace(self):
        cypher = "OPTIONAL   MATCH (n:AWSRole) RETURN n"
        result = _inject(cypher)
        assert f"(n:AWSRole:{LABEL})" in result

    def test_multiple_match_clauses(self):
        cypher = (
            "MATCH (a:AWSAccount)--(b:AWSRole) "
            "MATCH (b)--(c:AWSPolicy) "
            "RETURN a, b, c"
        )
        result = _inject(cypher)
        assert f"(a:AWSAccount:{LABEL})" in result
        assert f"(b:AWSRole:{LABEL})" in result
        assert f"(c:AWSPolicy:{LABEL})" in result
        # (b) in second MATCH is bare and gets injected
        assert result.count(LABEL) == 4  # a, b (labeled), b (bare in 2nd MATCH), c


# ---------------------------------------------------------------------------
# Real-world query patterns from aws.py
# ---------------------------------------------------------------------------


class TestRealWorldQueries:
    def test_basic_resource_query(self):
        cypher = (
            "MATCH path = (aws:AWSAccount {id: $provider_uid})--(rds:RDSInstance)\n"
            "UNWIND nodes(path) as n\n"
            "OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding {status: 'FAIL'})\n"
            "RETURN path, collect(DISTINCT pf) as dpf"
        )
        result = _inject(cypher)
        assert f"(aws:AWSAccount:{LABEL} {{id: $provider_uid}})" in result
        assert f"(rds:RDSInstance:{LABEL})" in result
        assert f"(n:{LABEL})" in result
        assert f"(pf:ProwlerFinding:{LABEL} {{status: 'FAIL'}})" in result
        assert "nodes(path)" in result  # function call untouched
        assert "collect(DISTINCT pf)" in result  # function call untouched

    def test_privilege_escalation_query(self):
        cypher = (
            "MATCH path_principal = (aws:AWSAccount {id: $uid})"
            "--(principal:AWSPrincipal)--(pol:AWSPolicy)\n"
            "WHERE pol.effect = 'Allow'\n"
            "MATCH (principal)--(cfn_policy:AWSPolicy)"
            "--(stmt_cfn:AWSPolicyStatement)\n"
            "WHERE any(action IN stmt_cfn.action WHERE toLower(action) = 'iam:passrole')\n"
            "MATCH path_target = (aws)--(target_role:AWSRole)"
            "-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {arn: 'cloudformation.amazonaws.com'})\n"
            "RETURN path_principal, path_target"
        )
        result = _inject(cypher)
        assert f"(aws:AWSAccount:{LABEL} {{id: $uid}})" in result
        assert f"(principal:AWSPrincipal:{LABEL})" in result
        assert f"(pol:AWSPolicy:{LABEL})" in result
        assert f"(principal:{LABEL})" in result  # bare in 2nd MATCH
        assert f"(cfn_policy:AWSPolicy:{LABEL})" in result
        assert f"(stmt_cfn:AWSPolicyStatement:{LABEL})" in result
        assert f"(aws:{LABEL})" in result  # bare in 3rd MATCH
        assert f"(target_role:AWSRole:{LABEL})" in result
        assert (
            f"(:AWSPrincipal:{LABEL} {{arn: 'cloudformation.amazonaws.com'}})" in result
        )
        # Function calls in WHERE untouched
        assert "any(action IN" in result
        assert "toLower(action)" in result

    def test_custom_bare_query(self):
        cypher = (
            "MATCH (a)-[:HAS_POLICY]->(b)\n"
            "WHERE a.name CONTAINS 'admin'\n"
            "RETURN a, b"
        )
        result = _inject(cypher)
        assert f"(a:{LABEL})" in result
        assert f"(b:{LABEL})" in result
        assert result.count(LABEL) == 2

    def test_internet_via_path_connectivity(self):
        """Post-refactor pattern: Internet reached via CAN_ACCESS, not standalone."""
        cypher = (
            "MATCH path = (aws:AWSAccount {id: $provider_uid})--(ec2:EC2Instance)\n"
            "WHERE ec2.exposed_internet = true\n"
            "OPTIONAL MATCH (internet:Internet)-[can_access:CAN_ACCESS]->(ec2)\n"
            "RETURN path, internet, can_access"
        )
        result = _inject(cypher)
        assert f"(aws:AWSAccount:{LABEL}" in result
        assert f"(ec2:EC2Instance:{LABEL})" in result
        assert f"(internet:Internet:{LABEL})" in result
        # ec2 in OPTIONAL MATCH is bare, but already labeled via Pass A won't match it
        # because it has no label. It IS bare, so Pass B injects.
        assert f"(ec2:{LABEL})" in result


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_query(self):
        assert _inject("") == ""

    def test_no_node_patterns(self):
        cypher = "RETURN 1 + 2"
        assert _inject(cypher) == cypher

    def test_anonymous_empty_parens_not_injected(self):
        """Empty () in MATCH is extremely rare but should not be injected."""
        cypher = "MATCH ()--(m:AWSRole) RETURN m"
        result = _inject(cypher)
        assert "()" in result  # empty parens untouched
        assert f"(m:AWSRole:{LABEL})" in result

    def test_fully_anonymous_query_bypasses_injection(self):
        """All-anonymous patterns bypass injection entirely.

        MATCH ()--()--() has no labels and no variables, so neither Pass A
        (labeled) nor Pass B (bare identifier) can inject the provider label.
        This is safe because _serialize_graph() (Layer 3) filters every
        returned node by provider label, dropping cross-provider data before
        it reaches the user.
        """
        cypher = "MATCH ()--()--() RETURN *"
        result = _inject(cypher)
        assert result == cypher  # completely unmodified
        assert LABEL not in result

    def test_relationship_patterns_untouched(self):
        cypher = "MATCH (a:X)-[r:REL_TYPE {x: 1}]->(b:Y) RETURN a"
        result = _inject(cypher)
        assert "[r:REL_TYPE {x: 1}]" in result  # relationship untouched
        assert f"(a:X:{LABEL})" in result
        assert f"(b:Y:{LABEL})" in result

    def test_call_subquery(self):
        cypher = (
            "CALL {\n"
            "  MATCH (inner:AWSRole) RETURN inner\n"
            "}\n"
            "MATCH (outer:AWSAccount) RETURN outer, inner"
        )
        result = _inject(cypher)
        assert f"(inner:AWSRole:{LABEL})" in result
        assert f"(outer:AWSAccount:{LABEL})" in result

    def test_multiple_protected_regions(self):
        cypher = (
            "MATCH (n:X {a: 'hello'}) " 'WHERE n.b = "world" ' "// comment\n" "RETURN n"
        )
        result = _inject(cypher)
        assert "'hello'" in result
        assert '"world"' in result
        assert "// comment" in result
        assert f"(n:X:{LABEL}" in result

    def test_idempotent_on_already_injected(self):
        """Running injection twice should add the label twice (not ideal, but predictable)."""
        first = _inject("MATCH (n:AWSRole) RETURN n")
        second = _inject(first)
        # The label appears twice (stacked)
        assert second.count(LABEL) == 2


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidation:
    @pytest.mark.parametrize(
        "cypher",
        [
            "LOAD CSV FROM 'http://169.254.169.254/' AS x RETURN x",
            "load csv from 'http://evil.com' as row return row",
            "CALL apoc.load.json('http://evil.com/') YIELD value RETURN value",
            "CALL apoc.load.csvParams('http://evil.com/', {}, null) YIELD list RETURN list",
            "CALL apoc.import.csv([{fileName: 'f'}], [], {}) YIELD node RETURN node",
            "CALL apoc.export.csv.all('file.csv', {})",
            "CALL apoc.cypher.run('CREATE (n)', {}) YIELD value RETURN value",
            "CALL apoc.systemdb.graph() YIELD nodes RETURN nodes",
            "CALL apoc.config.list() YIELD key, value RETURN key, value",
            "CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DELETE n', {batchSize: 100})",
            "CALL apoc.do.when(true, 'CREATE (n) RETURN n', '', {}) YIELD value RETURN value",
            "CALL apoc.trigger.add('t', 'RETURN 1', {phase: 'before'})",
            "CALL apoc.custom.asProcedure('myProc', 'RETURN 1')",
        ],
        ids=[
            "LOAD_CSV",
            "LOAD_CSV_lowercase",
            "apoc.load.json",
            "apoc.load.csvParams",
            "apoc.import.csv",
            "apoc.export.csv",
            "apoc.cypher.run",
            "apoc.systemdb.graph",
            "apoc.config.list",
            "apoc.periodic.iterate",
            "apoc.do.when",
            "apoc.trigger.add",
            "apoc.custom.asProcedure",
        ],
    )
    def test_rejects_blocked_patterns(self, cypher):
        with pytest.raises(ValidationError) as exc:
            validate_custom_query(cypher)

        assert "blocked operation" in str(exc.value.detail)

    @pytest.mark.parametrize(
        "cypher",
        [
            "MATCH (n:AWSAccount) RETURN n LIMIT 10",
            "MATCH (a)-[r]->(b) RETURN a, r, b",
            "MATCH (n) WHERE n.name CONTAINS 'load' RETURN n",
            "CALL apoc.create.vNode(['Label'], {}) YIELD node RETURN node",
            "MATCH (n) WHERE n.name = 'apoc.load.json' RETURN n",
            'MATCH (n) WHERE n.description = "LOAD CSV is cool" RETURN n',
        ],
        ids=[
            "simple_match",
            "traversal",
            "contains_load_substring",
            "apoc_virtual_node",
            "apoc_load_inside_single_quotes",
            "load_csv_inside_double_quotes",
        ],
    )
    def test_allows_clean_queries(self, cypher):
        validate_custom_query(cypher)
