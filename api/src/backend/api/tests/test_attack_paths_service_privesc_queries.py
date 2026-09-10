"""
Structural validation for the pathfinding.cloud service privilege-escalation
Attack Paths queries added in PROWLER-2279.

These assert the conventions documented in
`docs/developer-guide/attack-paths-queries.mdx`: list-typed policy properties are
reached through `HAS_*` child-item traversals (never read as node fields),
predicate functions unsupported on Neptune (`any`/`all`/`none`, regex `=~`) are
absent, the finding probe is typed and filters only on `status`, and the
`RETURN` shape preserves the `paths, dpf, dpfr` contract.
"""

import re

import pytest
from api.attack_paths.queries.aws import AWS_QUERIES
from api.attack_paths.queries.types import AttackPathsQueryDefinition

# IDs of the queries introduced for PROWLER-2279 (pathfinding.cloud coverage).
PATHFINDING_2279_QUERY_IDS = [
    "aws-batch-privesc-passrole-submit-job",
    "aws-braket-privesc-passrole-create-job",
    "aws-cognito-privesc-passrole-set-identity-pool-roles",
    "aws-ecs-privesc-passrole-start-existing-task",
    "aws-emr-privesc-passrole-run-job-flow",
    "aws-emrserverless-privesc-passrole-start-job",
    "aws-gamelift-privesc-passrole-create-fleet",
    "aws-glue-privesc-passrole-create-session",
    "aws-imagebuilder-privesc-passrole-create-image",
    "aws-kinesisanalytics-privesc-passrole-create-application",
    "aws-omics-privesc-passrole-start-run",
    "aws-scheduler-privesc-passrole-create-schedule",
    "aws-ssm-privesc-passrole-automation",
    "aws-stepfunctions-privesc-passrole-create-state-machine",
    "aws-batch-privesc-submit-existing-job",
    "aws-codedeploy-privesc-create-deployment",
    "aws-stepfunctions-privesc-update-state-machine",
    "aws-iam-privesc-delete-role-boundary-assume-role",
    "aws-sso-privesc-attach-managed-policy-permission-set",
    "aws-sso-privesc-put-inline-policy-permission-set",
]

_BY_ID = {q.id: q for q in AWS_QUERIES}
NEW_QUERIES = [_BY_ID[qid] for qid in PATHFINDING_2279_QUERY_IDS if qid in _BY_ID]

NEPTUNE_UNSUPPORTED_PREDICATES = re.compile(r"\b(any|all|none)\s*\(", re.IGNORECASE)
NORMALIZED_STATEMENT_FIELDS = ("action", "resource", "notaction", "notresource")


def test_all_2279_queries_registered():
    missing = [qid for qid in PATHFINDING_2279_QUERY_IDS if qid not in _BY_ID]
    assert not missing, f"queries not registered in AWS_QUERIES: {missing}"


class TestServicePrivescQuerySchema:
    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_is_query_definition(self, query):
        assert isinstance(query, AttackPathsQueryDefinition)

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_id_kebab_and_aws_prefixed(self, query):
        assert query.id.startswith("aws-")
        assert re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", query.id)

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_provider_is_aws(self, query):
        assert query.provider == "aws"

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_has_metadata(self, query):
        assert query.name and len(query.name) > 5
        assert query.short_description and len(query.short_description) > 10
        assert query.description and len(query.description) > 20
        assert isinstance(query.parameters, list)

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_attribution_links_pathfinding(self, query):
        assert query.attribution is not None
        assert "pathfinding.cloud" in query.attribution.text
        assert query.attribution.link.startswith("https://pathfinding.cloud/paths/")


class TestServicePrivescQueryCypher:
    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_anchored_and_provider_scoped(self, query):
        assert "(aws:AWSAccount {id: $provider_uid})" in query.cypher

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_finding_label_interpolated(self, query):
        assert "PROWLER_FINDING_LABEL" not in query.cypher

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_typed_status_scoped_finding_probe(self, query):
        assert re.search(
            r"-\[pfr:HAS_FINDING\]-\(pf:ProwlerFinding \{status: 'FAIL'\}\)",
            query.cypher,
        ), f"{query.id} lacks the typed, status-scoped finding probe"

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_return_contract(self, query):
        assert re.search(
            r"RETURN paths, collect\(DISTINCT pf\) as dpf, "
            r"collect\(DISTINCT pfr\) as dpfr",
            query.cypher,
        )

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_no_neptune_unsupported_predicates(self, query):
        m = NEPTUNE_UNSUPPORTED_PREDICATES.search(query.cypher)
        assert m is None, f"{query.id} uses '{m.group().strip()}' (not Neptune-safe)"

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_no_regex_operator(self, query):
        assert "=~" not in query.cypher

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_does_not_read_normalized_list_fields(self, query):
        for field in NORMALIZED_STATEMENT_FIELDS:
            assert not re.search(rf"\.{field}\b", query.cypher), (
                f"{query.id} reads normalized list field '.{field}' as a property; "
                f"traverse the HAS_{field.upper()} edge instead"
            )

    @pytest.mark.parametrize("query", NEW_QUERIES, ids=lambda q: q.id)
    def test_read_only(self, query):
        no_comments = "\n".join(
            line
            for line in query.cypher.split("\n")
            if not line.strip().startswith("//")
        )
        assert not re.search(
            r"\b(CREATE|MERGE|SET|DELETE|REMOVE|DETACH)\b", no_comments, re.IGNORECASE
        )
