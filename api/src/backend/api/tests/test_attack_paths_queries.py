"""
Structural validation tests for Attack Paths query definitions.

These tests verify that each query in the AWS_QUERIES registry meets the
schema and convention requirements without requiring a live Neo4j connection.
"""

import re

import pytest

from api.attack_paths.queries.aws import (
    AWS_IAM_PRIVESC_BOUNDARY_REMOVAL,
    AWS_IAM_PRIVESC_CROSS_ACCOUNT_NO_EXTERNAL_ID,
    AWS_IAM_PRIVESC_CREATE_POLICY_VERSION_SELF_ESCALATION,
    AWS_IAM_PRIVESC_PASSROLE_EC2,
    AWS_IAM_PRIVESC_PASSROLE_LAMBDA,
    AWS_IAM_PRIVESC_UPDATE_TRUST_SELF_ASSUME,
    AWS_IAM_PRIVESC_WILDCARD_TRUST,
    AWS_QUERIES,
    AWS_SSO_PRIVESC_PERMISSION_SET_ESCALATION,
)
from api.attack_paths.queries.types import AttackPathsQueryDefinition


# All 8 new IAM privilege escalation queries
NEW_IAM_PRIVESC_QUERIES = [
    AWS_IAM_PRIVESC_CROSS_ACCOUNT_NO_EXTERNAL_ID,
    AWS_IAM_PRIVESC_WILDCARD_TRUST,
    AWS_IAM_PRIVESC_UPDATE_TRUST_SELF_ASSUME,
    AWS_IAM_PRIVESC_PASSROLE_LAMBDA,
    AWS_IAM_PRIVESC_PASSROLE_EC2,
    AWS_IAM_PRIVESC_CREATE_POLICY_VERSION_SELF_ESCALATION,
    AWS_IAM_PRIVESC_BOUNDARY_REMOVAL,
    AWS_SSO_PRIVESC_PERMISSION_SET_ESCALATION,
]

# Cypher keywords that indicate mutating queries (not allowed)
MUTATING_KEYWORDS = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|REMOVE|DETACH)\b", re.IGNORECASE
)

# Cypher CALL subquery pattern (not compatible with Neptune openCypher)
CALL_SUBQUERY_PATTERN = re.compile(r"\bCALL\s*\{", re.IGNORECASE)


class TestNewIAMPrivescQueriesRegistered:
    """Verify all 8 new queries are present in the AWS_QUERIES registry."""

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_query_in_registry(self, query):
        assert query in AWS_QUERIES


class TestNewIAMPrivescQueriesSchema:
    """Validate required fields and conventions for each new query."""

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_is_query_definition_instance(self, query):
        assert isinstance(query, AttackPathsQueryDefinition)

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_id_is_kebab_case(self, query):
        assert re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", query.id), (
            f"Query id '{query.id}' is not kebab-case"
        )

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_id_starts_with_aws(self, query):
        assert query.id.startswith("aws-")

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_provider_is_aws(self, query):
        assert query.provider == "aws"

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_has_name(self, query):
        assert query.name and len(query.name) > 5

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_has_short_description(self, query):
        assert query.short_description and len(query.short_description) > 10

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_has_description(self, query):
        assert query.description and len(query.description) > 20

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_has_attribution(self, query):
        assert query.attribution is not None
        assert "pathfinding.cloud" in query.attribution.text
        assert query.attribution.link.startswith("https://pathfinding.cloud/paths/")

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_parameters_is_list(self, query):
        assert isinstance(query.parameters, list)


class TestNewIAMPrivescQueriesCypher:
    """Validate Cypher query content and conventions."""

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_cypher_not_empty(self, query):
        assert query.cypher and len(query.cypher.strip()) > 0

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_cypher_under_10000_chars(self, query):
        assert len(query.cypher) < 10000, (
            f"Query {query.id} exceeds 10,000 character limit ({len(query.cypher)} chars)"
        )

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_cypher_uses_provider_uid_parameter(self, query):
        assert "$provider_uid" in query.cypher, (
            f"Query {query.id} missing $provider_uid parameter"
        )

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_cypher_has_prowler_finding_join(self, query):
        # The f-string should have interpolated PROWLER_FINDING_LABEL already
        assert "PROWLER_FINDING_LABEL" not in query.cypher, (
            f"Query {query.id} has unresolved PROWLER_FINDING_LABEL (f-string not applied)"
        )
        # The interpolated label and status filter should be present
        assert "status: 'FAIL'" in query.cypher

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_cypher_is_read_only(self, query):
        # Strip comments before checking for mutation keywords
        lines = [
            line
            for line in query.cypher.split("\n")
            if not line.strip().startswith("//")
        ]
        cypher_no_comments = "\n".join(lines)
        match = MUTATING_KEYWORDS.search(cypher_no_comments)
        assert match is None, (
            f"Query {query.id} contains mutating keyword: '{match.group()}'"
        )

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_cypher_no_call_subquery(self, query):
        assert not CALL_SUBQUERY_PATTERN.search(query.cypher), (
            f"Query {query.id} uses CALL subquery (not Neptune-compatible)"
        )

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_cypher_returns_paths(self, query):
        assert "RETURN" in query.cypher, f"Query {query.id} missing RETURN statement"

    @pytest.mark.parametrize("query", NEW_IAM_PRIVESC_QUERIES, ids=lambda q: q.id)
    def test_cypher_collects_findings(self, query):
        assert "collect(DISTINCT pf)" in query.cypher, (
            f"Query {query.id} missing findings collection"
        )


class TestAllQueriesUniqueIds:
    """Ensure no duplicate IDs in the full registry."""

    def test_no_duplicate_ids_in_aws_queries(self):
        ids = [q.id for q in AWS_QUERIES]
        duplicates = [qid for qid in ids if ids.count(qid) > 1]
        assert not duplicates, f"Duplicate query IDs found: {set(duplicates)}"
