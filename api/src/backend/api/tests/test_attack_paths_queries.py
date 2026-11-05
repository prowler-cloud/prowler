"""
Structural validation tests for Attack Paths query definitions.

These tests verify that each query in the AWS_QUERIES registry meets the
schema and convention requirements documented in
`docs/developer-guide/attack-paths-queries.mdx` without requiring a live
graph connection. They deliberately assert the conventions that keep queries
functional and Neptune-compatible: list-typed policy properties are reached
through `HAS_*` child-item traversals (never read as node fields), predicate
functions unsupported on Neptune (`any`/`all`/`none`, regex `=~`) are absent,
the finding probe is typed and filters only on `status`, and the `RETURN`
shape preserves the `paths, dpf, dpfr` contract.
"""

import re

import pytest
from api.attack_paths.queries.aws import (
    AWS_IAM_PRIVESC_DELETE_USER_PERMISSIONS_BOUNDARY,
    AWS_QUERIES,
    AWS_SSO_PRIVESC_PERMISSION_SET_ESCALATION,
    AWS_STS_PRIVESC_CROSS_ACCOUNT_TRUST,
    AWS_STS_PRIVESC_WILDCARD_TRUST,
)
from api.attack_paths.queries.types import (
    AttackPathsQueryDefinition,
    AttackPathsQueryOutcome,
)

# The pathfinding.cloud privilege-escalation queries added for PROWLER-2278.
NEW_PATHFINDING_QUERIES = [
    AWS_STS_PRIVESC_CROSS_ACCOUNT_TRUST,
    AWS_STS_PRIVESC_WILDCARD_TRUST,
    AWS_IAM_PRIVESC_DELETE_USER_PERMISSIONS_BOUNDARY,
    AWS_SSO_PRIVESC_PERMISSION_SET_ESCALATION,
]

# Cypher keywords that indicate a mutating query (not allowed; queries are read-only).
MUTATING_KEYWORDS = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|REMOVE|DETACH)\b", re.IGNORECASE
)

# CALL subquery: unsupported by Neptune openCypher.
CALL_SUBQUERY_PATTERN = re.compile(r"\bCALL\s*\{", re.IGNORECASE)

# Predicate functions that are not part of the openCypher spec and fail on Neptune.
NEPTUNE_UNSUPPORTED_PREDICATES = re.compile(r"\b(any|all|none)\s*\(", re.IGNORECASE)

# The list-typed policy properties that are exploded into child item nodes at sync
# time and popped off the parent, so reading them as a field always yields null.
NORMALIZED_STATEMENT_FIELDS = ("action", "resource", "notaction", "notresource")


class TestNewPathfindingQueriesRegistered:
    """Every new query is present in the AWS_QUERIES registry."""

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_query_in_registry(self, query):
        assert query in AWS_QUERIES


class TestNewPathfindingQueriesSchema:
    """Required fields and naming conventions for each new query."""

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_is_query_definition_instance(self, query):
        assert isinstance(query, AttackPathsQueryDefinition)

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_id_is_kebab_case(self, query):
        assert re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", query.id), (
            f"Query id '{query.id}' is not kebab-case"
        )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_id_starts_with_aws(self, query):
        assert query.id.startswith("aws-")

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_provider_is_aws(self, query):
        assert query.provider == "aws"

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_has_name(self, query):
        assert query.name and len(query.name) > 5

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_has_short_description(self, query):
        assert query.short_description and len(query.short_description) > 10

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_has_description(self, query):
        assert query.description and len(query.description) > 20

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_has_attribution(self, query):
        assert query.attribution is not None
        assert "pathfinding.cloud" in query.attribution.text
        assert query.attribution.link.startswith("https://pathfinding.cloud/paths/")

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_parameters_is_list(self, query):
        assert isinstance(query.parameters, list)


class TestNewPathfindingQueriesCypher:
    """Cypher content, conventions, and Neptune compatibility."""

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_not_empty(self, query):
        assert query.cypher and len(query.cypher.strip()) > 0

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_under_10000_chars(self, query):
        assert len(query.cypher) < 10000, (
            f"Query {query.id} exceeds 10,000 character limit "
            f"({len(query.cypher)} chars)"
        )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_uses_provider_uid_parameter(self, query):
        assert "$provider_uid" in query.cypher, (
            f"Query {query.id} missing $provider_uid parameter"
        )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_finding_label_interpolated(self, query):
        # The f-string should have interpolated PROWLER_FINDING_LABEL already.
        assert "PROWLER_FINDING_LABEL" not in query.cypher, (
            f"Query {query.id} has unresolved PROWLER_FINDING_LABEL "
            "(f-string not applied)"
        )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_finding_probe_is_typed_and_status_scoped(self, query):
        # The finding probe must be typed HAS_FINDING (so Neptune applies an inline
        # edge filter) and gate on FAIL status only. ProwlerFinding nodes carry no
        # provider_uid property, so a probe that filters on it never matches.
        assert re.search(
            r"-\[pfr:HAS_FINDING\]-\(pf:ProwlerFinding \{status: 'FAIL'\}\)",
            query.cypher,
        ), f"Query {query.id} does not use the typed, status-scoped finding probe"
        assert "provider_uid:$provider_uid}" not in query.cypher.replace(" ", ""), (
            f"Query {query.id} filters the finding node on a non-existent "
            "provider_uid property"
        )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_is_read_only(self, query):
        cypher_no_comments = _strip_comment_lines(query.cypher)
        match = MUTATING_KEYWORDS.search(cypher_no_comments)
        assert match is None, (
            f"Query {query.id} contains mutating keyword: '{match.group()}'"
        )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_no_call_subquery(self, query):
        assert not CALL_SUBQUERY_PATTERN.search(query.cypher), (
            f"Query {query.id} uses a CALL subquery (not Neptune-compatible)"
        )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_no_neptune_unsupported_predicates(self, query):
        match = NEPTUNE_UNSUPPORTED_PREDICATES.search(query.cypher)
        assert match is None, (
            f"Query {query.id} uses '{match.group().strip()}' predicate function; "
            "use size([x IN list WHERE pred]) > 0 for Neptune compatibility"
        )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_no_regex_operator(self, query):
        assert "=~" not in query.cypher, (
            f"Query {query.id} uses the regex operator '=~'; "
            "use CONTAINS / STARTS WITH for Neptune compatibility"
        )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_does_not_read_normalized_list_fields(self, query):
        # action/resource/notaction/notresource are materialized as child item nodes
        # and popped off AWSPolicyStatement, so `stmt.action` etc. are always null.
        for field in NORMALIZED_STATEMENT_FIELDS:
            assert not re.search(rf"\.{field}\b", query.cypher), (
                f"Query {query.id} reads the normalized list field "
                f"'.{field}' as a node property; traverse the HAS_"
                f"{field.upper()} edge to the child item node instead"
            )

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_preserves_return_contract(self, query):
        assert re.search(
            r"RETURN paths, collect\(DISTINCT pf\) as dpf, "
            r"collect\(DISTINCT pfr\) as dpfr",
            query.cypher,
        ), f"Query {query.id} does not preserve the 'paths, dpf, dpfr' RETURN contract"

    @pytest.mark.parametrize("query", NEW_PATHFINDING_QUERIES, ids=lambda q: q.id)
    def test_cypher_anchored_on_account(self, query):
        assert "(aws:AWSAccount {id: $provider_uid})" in query.cypher, (
            f"Query {query.id} is not anchored on the AWSAccount node"
        )


class TestNewPathfindingQueriesAccuracy:
    """Query-specific contracts that prevent known false positives."""

    def test_wildcard_trust_is_presented_as_a_manual_review_candidate(self):
        query = AWS_STS_PRIVESC_WILDCARD_TRUST
        text = f"{query.name} {query.short_description} {query.description}".lower()
        assert all(
            word in text
            for word in ("potential", "effect", "condition", "manual review")
        )

    def test_permissions_boundary_removal_is_scoped_to_the_same_user(self):
        query = AWS_IAM_PRIVESC_DELETE_USER_PERMISSIONS_BOUNDARY
        assert "(principal:AWSUser)" in query.cypher
        assert (
            "(stmt)-[:HAS_RESOURCE]->(res:AWSPolicyStatementResourceItem)"
            in query.cypher
        )
        assert "principal.arn" in query.cypher
        assert "manual review" in query.description.lower()

    def test_permission_set_escalation_requires_global_resources(self):
        query = AWS_SSO_PRIVESC_PERMISSION_SET_ESCALATION
        for suffix in ("", "2", "3"):
            resource_match = (
                f"(stmt{suffix})-[:HAS_RESOURCE]->"
                f"(res{suffix}:AWSPolicyStatementResourceItem)"
            )
            assert resource_match in query.cypher
            assert f"WHERE res{suffix}.value = '*'" in query.cypher


class TestAllQueriesUniqueIds:
    """No duplicate IDs in the full registry."""

    def test_no_duplicate_ids_in_aws_queries(self):
        ids = [q.id for q in AWS_QUERIES]
        duplicates = sorted({qid for qid in ids if ids.count(qid) > 1})
        assert not duplicates, f"Duplicate query IDs found: {duplicates}"


class TestQueryOutcomes:
    """Every query carries a valid outcome (the graph's terminal impact)."""

    def test_every_query_has_an_outcome(self):
        # Completeness guard: a new query must be given an outcome, so the UI can
        # always render a terminal outcome node.
        missing = [q.id for q in AWS_QUERIES if q.outcome is None]
        assert not missing, f"Queries without an outcome: {missing}"

    def test_every_outcome_is_a_valid_member(self):
        for query in AWS_QUERIES:
            assert isinstance(query.outcome, AttackPathsQueryOutcome)
            assert query.outcome.value.kind
            assert query.outcome.value.label

    @pytest.mark.parametrize(
        "query, expected",
        [
            (
                AWS_STS_PRIVESC_CROSS_ACCOUNT_TRUST,
                AttackPathsQueryOutcome.PRIVILEGE_ESCALATION,
            ),
            (
                AWS_IAM_PRIVESC_DELETE_USER_PERMISSIONS_BOUNDARY,
                AttackPathsQueryOutcome.PRIVILEGE_ESCALATION,
            ),
        ],
        ids=lambda v: getattr(v, "id", getattr(v, "name", "")),
    )
    def test_representative_outcomes(self, query, expected):
        assert query.outcome is expected

    def test_inventory_outcome_is_partial(self):
        assert AttackPathsQueryOutcome.RESOURCE_INVENTORY.value.partial is True

    def test_realized_outcomes_are_not_partial(self):
        for outcome in (
            AttackPathsQueryOutcome.CODE_EXECUTION,
            AttackPathsQueryOutcome.PRIVILEGE_ESCALATION,
            AttackPathsQueryOutcome.PUBLIC_EXPOSURE,
        ):
            assert outcome.value.partial is False


def _strip_comment_lines(cypher: str) -> str:
    """Drop `//` comment lines so keyword scans ignore prose in comments."""
    return "\n".join(
        line for line in cypher.split("\n") if not line.strip().startswith("//")
    )
