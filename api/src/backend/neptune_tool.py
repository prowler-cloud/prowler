"""Throwaway Neptune/Neo4j sink inspection tool. Not committed.

Run inside the API container:

    docker exec -it <api-container> \
        python src/backend/neptune_tool.py [options]

Modes:
    --summary             fast cluster-wide node/edge counts via the Neptune
                          statistics API (no scan; may lag recent writes;
                          ignores tenant/provider label isolation)
    --label LABEL         count only nodes carrying LABEL (e.g. AWSRole)
    --rels                also count relationships
    --cypher "..."        run an arbitrary read query over Bolt, print rows
    --explain "..."       Neptune openCypher EXPLAIN plan for the query
                          (HTTP, SigV4-signed; not available over Bolt)
    --explain-mode M      static | dynamic | details   (default: details)
    --provider-uid UID    bind $provider_uid in --explain / --cypher
    --param K=V           bind an extra parameter (repeatable)

`--summary` and `--explain` hit Neptune's HTTPS endpoint directly and need:
    ATTACK_PATHS_SINK_DATABASE=neptune
    NEPTUNE_WRITER_ENDPOINT / NEPTUNE_READER_ENDPOINT / AWS_REGION

The openCypher counts under --label/--cypher are full scans and will hit
Neptune's server-side timeout on a very large graph; --summary and --explain
do not scan.
"""

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request

import django

# manage.py lives next to this file; make `config`, `api`, `tasks` importable.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.devel")
django.setup()

import neo4j  # noqa: E402

from botocore.auth import SigV4Auth  # noqa: E402
from botocore.awsrequest import AWSRequest  # noqa: E402
from botocore.session import Session as BotoSession  # noqa: E402

from api.attack_paths import sink as sink_module  # noqa: E402


def _neptune_endpoint() -> tuple[str, str, str]:
    """Return (endpoint, port, region) for the configured Neptune sink."""
    from django.conf import settings

    cfg = settings.DATABASES["neptune"]
    endpoint = cfg["READER_ENDPOINT"] or cfg["WRITER_ENDPOINT"]
    port = cfg["PORT"]
    region = cfg["REGION"]
    if not endpoint or not region:
        print(
            "NEPTUNE_READER_ENDPOINT/NEPTUNE_WRITER_ENDPOINT and AWS_REGION "
            "must be set for --summary/--explain.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return endpoint, port, region


def _signed_request(
    method: str,
    url: str,
    region: str,
    body: str | None = None,
    content_type: str | None = None,
) -> urllib.request.Request:
    """Build a SigV4-signed urllib request for the Neptune data plane."""
    credentials = BotoSession().get_credentials()
    if credentials is None:
        print("No AWS credentials available for SigV4 signing.", file=sys.stderr)
        raise SystemExit(1)
    credentials = credentials.get_frozen_credentials()

    headers = {}
    if content_type:
        headers["Content-Type"] = content_type

    data = body.encode() if body is not None else None
    aws_request = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(credentials, "neptune-db", region).add_auth(aws_request)

    req = urllib.request.Request(url, data=data, method=method)
    for header, value in aws_request.headers.items():
        req.add_header(header, value)
    return req


def _statistics_summary() -> int:
    endpoint, port, region = _neptune_endpoint()
    url = f"https://{endpoint}:{port}/propertygraph/statistics/summary?mode=detailed"
    req = _signed_request("GET", url, region)
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read())

    summary = payload.get("payload", {}).get("graphSummary", {})
    print(f"numNodes: {summary.get('numNodes')}")
    print(f"numEdges: {summary.get('numEdges')}")
    print(f"numNodeLabels: {summary.get('numNodeLabels')}")
    print(f"numEdgeLabels: {summary.get('numEdgeLabels')}")
    print(
        "(cluster-wide; reflects last statistics computation, "
        "may lag recent writes; ignores tenant/provider labels)"
    )
    return 0


def _explain(cypher: str, mode: str, parameters: dict) -> int:
    endpoint, port, region = _neptune_endpoint()
    url = f"https://{endpoint}:{port}/opencypher"

    form = {"query": cypher, "explain": mode}
    if parameters:
        form["parameters"] = json.dumps(parameters)
    body = urllib.parse.urlencode(form)

    req = _signed_request(
        "POST",
        url,
        region,
        body=body,
        content_type="application/x-www-form-urlencoded",
    )
    try:
        with urllib.request.urlopen(req, timeout=1800) as resp:
            print(resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}", file=sys.stderr)
        print(exc.read().decode(errors="replace"), file=sys.stderr)
        return 1
    return 0


def _parse_params(args: argparse.Namespace) -> dict:
    params: dict = {}
    for pair in args.param or []:
        if "=" not in pair:
            print(f"--param expects KEY=VALUE, got {pair!r}", file=sys.stderr)
            raise SystemExit(1)
        key, value = pair.split("=", 1)
        params[key] = value
    if args.provider_uid:
        params["provider_uid"] = args.provider_uid
    return params


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect the Neptune/Neo4j sink")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--label")
    parser.add_argument("--rels", action="store_true")
    parser.add_argument("--cypher")
    parser.add_argument("--explain", dest="explain", metavar="CYPHER")
    parser.add_argument(
        "--explain-mode",
        dest="explain_mode",
        choices=["static", "dynamic", "details"],
        default="details",
    )
    parser.add_argument("--provider-uid", dest="provider_uid")
    parser.add_argument("--param", action="append", help="KEY=VALUE (repeatable)")
    args = parser.parse_args()

    from django.conf import settings

    print(f"ATTACK_PATHS_SINK_DATABASE = {settings.ATTACK_PATHS_SINK_DATABASE}")

    if args.explain:
        if settings.ATTACK_PATHS_SINK_DATABASE != "neptune":
            print("--explain requires the Neptune sink.", file=sys.stderr)
            return 1
        return _explain(args.explain, args.explain_mode, _parse_params(args))

    if settings.ATTACK_PATHS_SINK_DATABASE != "neptune":
        print(
            "Warning: sink is not Neptune; this still runs against the active sink.",
            file=sys.stderr,
        )

    if args.summary:
        return _statistics_summary()

    backend = sink_module.get_backend()
    with backend.get_session(default_access_mode=neo4j.READ_ACCESS) as session:
        if args.cypher:
            for record in session.run(args.cypher, _parse_params(args)):
                print(dict(record))
            return 0

        if args.label:
            node_query = f"MATCH (n:`{args.label}`) RETURN count(n) AS c"
        else:
            node_query = "MATCH (n) RETURN count(n) AS c"

        node_count = session.run(node_query).single()["c"]
        scope = f" with label `{args.label}`" if args.label else ""
        print(f"nodes{scope}: {node_count}")

        if args.rels:
            rel_count = session.run(
                "MATCH ()-[r]->() RETURN count(r) AS c"
            ).single()["c"]
            print(f"relationships: {rel_count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
