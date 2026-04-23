"""SigV4 authentication for AWS Neptune Bolt connections.

Builds a short-lived (~5 minute) token that the neo4j driver rotates via
``ExpiringAuth``. Based on the recipe in NEPTUNE_READ_ONLY.md §4 Option B.
"""
from __future__ import annotations

import datetime
import json
from typing import Callable

import neo4j
from botocore.auth import SigV4Auth, _host_from_url
from botocore.awsrequest import AWSRequest
from botocore.session import Session as BotoSession
from neo4j import ExpiringAuth

# Refresh 60s before the 5-minute SigV4 window closes
TOKEN_LIFETIME_MINUTES = 4


class NeptuneAuthToken(neo4j.Auth):
    """Neo4j Auth backed by a SigV4-signed GET to ``/opencypher``."""

    def __init__(self, region: str, url: str) -> None:
        session = BotoSession()
        credentials = session.get_credentials()
        if credentials is None:
            raise RuntimeError(
                "No AWS credentials available for Neptune SigV4 signing. "
                "Ensure the boto3 credential chain can resolve."
            )
        credentials = credentials.get_frozen_credentials()

        request = AWSRequest(method="GET", url=url + "/opencypher")
        request.headers.add_header("Host", _host_from_url(request.url))
        SigV4Auth(credentials, "neptune-db", region).add_auth(request)

        auth_obj = {
            header: request.headers[header]
            for header in ("Authorization", "X-Amz-Date", "X-Amz-Security-Token", "Host")
            if header in request.headers
        }
        auth_obj["HttpMethod"] = "GET"

        super().__init__("basic", "username", json.dumps(auth_obj), "realm")


def neptune_auth_provider(region: str, https_url: str) -> Callable[[], ExpiringAuth]:
    """Return a callable the neo4j driver can invoke to refresh credentials."""

    def _provider() -> ExpiringAuth:
        token = NeptuneAuthToken(region, https_url)
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=TOKEN_LIFETIME_MINUTES
        )
        return ExpiringAuth(auth=token, expires_at=expires_at)

    return _provider
