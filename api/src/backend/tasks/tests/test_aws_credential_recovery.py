from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from io import BytesIO
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from boto3.session import Session
from botocore.awsrequest import AWSResponse
from botocore.credentials import ReadOnlyCredentials
from botocore.exceptions import ClientError
from prowler.providers.aws.exceptions.exceptions import AWSSessionTokenExpiredError
from tasks.jobs import aws_credential_recovery
from tasks.jobs.aws_credential_recovery import CredentialRecovery


class _Body(BytesIO):
    def stream(self, **kwargs):
        yield self.read()


def _s3_with_response(handler):
    session = Session(
        aws_access_key_id="OLD_KEY",
        aws_secret_access_key="OLD_SECRET",
        aws_session_token="OLD_TOKEN",
        region_name="us-east-1",
    )
    session.events.register("before-send.s3.ListBuckets", handler)
    return session


def _s3_response(request, code=None):
    if code:
        body = f"<Error><Code>{code}</Code><Message>Denied</Message></Error>".encode()
    else:
        body = b"<ListAllMyBucketsResult><Buckets /></ListAllMyBucketsResult>"
    return AWSResponse(request.url, 403 if code else 200, {}, _Body(body))


def test_running_client_resumes_with_replaced_direct_credentials():
    authorization: list[bytes] = []
    replacement = ReadOnlyCredentials("NEW_KEY", "NEW_SECRET", "NEW_TOKEN")

    def respond(request, **kwargs):
        authorization.append(request.headers["Authorization"])
        if len(authorization) == 2:
            return _s3_response(request, "ExpiredToken")
        return _s3_response(request)

    session = _s3_with_response(respond)
    # The old credentials are still stored on the first read.
    load = Mock(side_effect=[None, replacement])
    waiting = Mock()
    recovery = CredentialRecovery(
        session, load, waiting, wait_seconds=1, poll_seconds=0
    )
    client = session.client("s3")
    client.list_buckets()
    client.list_buckets()
    client.list_buckets()
    recovery.raise_if_failed()

    assert len(authorization) == 4
    assert all(b"Credential=OLD_KEY/" in auth for auth in authorization[:2])
    assert all(b"Credential=NEW_KEY/" in auth for auth in authorization[2:])
    assert [c.args for c in waiting.call_args_list] == [(True,), (False,)]


def test_parallel_requests_share_one_replacement():
    both_signed = Barrier(2)

    def respond(request, **kwargs):
        if b"Credential=OLD_KEY/" in request.headers["Authorization"]:
            both_signed.wait(timeout=5)
            return _s3_response(request, "ExpiredToken")
        return _s3_response(request)

    session = _s3_with_response(respond)
    load = Mock(return_value=ReadOnlyCredentials("NEW_KEY", "NEW_SECRET", "NEW_TOKEN"))
    waiting = Mock()
    recovery = CredentialRecovery(session, load, waiting, wait_seconds=0)
    client = session.client("s3")
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert len(list(pool.map(lambda _: client.list_buckets(), range(2)))) == 2

    load.assert_called_once()
    assert [c.args for c in waiting.call_args_list] == [(True,), (False,)]
    recovery.raise_if_failed()


def test_access_denied_does_not_wait_or_retry():
    def respond(request, **kwargs):
        return _s3_response(request, "AccessDenied")

    session = _s3_with_response(respond)
    load = Mock()
    waiting = Mock()
    recovery = CredentialRecovery(session, load, waiting, wait_seconds=0)

    with pytest.raises(ClientError, match="AccessDenied"):
        session.client("s3").list_buckets()

    load.assert_not_called()
    waiting.assert_not_called()
    recovery.raise_if_failed()


def test_expired_token_without_replacement_fails_the_scan():
    def respond(request, **kwargs):
        return _s3_response(request, "InvalidAccessKeyId")

    session = _s3_with_response(respond)
    load = Mock(return_value=None)
    waiting = Mock()
    recovery = CredentialRecovery(session, load, waiting, wait_seconds=0)

    with pytest.raises(ClientError, match="InvalidAccessKeyId"):
        session.client("s3").list_buckets()
    with pytest.raises(AWSSessionTokenExpiredError):
        recovery.raise_if_failed()

    load.assert_called_once()
    assert [c.args for c in waiting.call_args_list] == [(True,), (False,)]


@pytest.mark.parametrize("account", ["123456789012", "999999999999"])
def test_web_scan_only_resumes_with_the_same_aws_principal(monkeypatch, account):
    current = "123456789012"

    def respond(request, **kwargs):
        if b"Credential=OLD_KEY/" in request.headers["Authorization"]:
            return _s3_response(request, "ExpiredToken")
        return _s3_response(request)

    session = _s3_with_response(respond)
    provider = SimpleNamespace(
        id="provider",
        tenant_id="tenant",
        secret=SimpleNamespace(secret_type="static"),
    )
    scan = SimpleNamespace(id="scan")
    scanner = SimpleNamespace(
        session=SimpleNamespace(current_session=session),
        identity=SimpleNamespace(
            account=current,
            identity_arn=f"arn:aws:iam::{current}:user/scanner",
            user_id="USER",
            audited_regions={"us-east-1"},
        ),
    )
    provider_query = Mock()
    provider_query.select_related.return_value.filter.return_value.first.return_value = (
        provider
    )
    scan_query = Mock()
    scan_query.filter.return_value.update.return_value = 1

    monkeypatch.setattr(
        aws_credential_recovery, "rls_transaction", lambda tenant_id: nullcontext()
    )
    monkeypatch.setattr(
        aws_credential_recovery, "Provider", SimpleNamespace(objects=provider_query)
    )
    monkeypatch.setattr(
        aws_credential_recovery, "Scan", SimpleNamespace(objects=scan_query)
    )
    monkeypatch.setattr(aws_credential_recovery, "WAIT_SECONDS", 0)
    monkeypatch.setattr(
        aws_credential_recovery,
        "declared_provider_secret",
        lambda fresh: {
            "aws_access_key_id": "NEW_KEY",
            "aws_secret_access_key": "NEW_SECRET",
            "aws_session_token": "NEW_TOKEN",
        },
    )

    real_session = Session

    def candidate_session(**kwargs):
        candidate = real_session(**kwargs)

        def sts_response(request, **kwargs):
            body = f"""
                <GetCallerIdentityResponse>
                  <GetCallerIdentityResult>
                    <Account>{account}</Account>
                    <Arn>arn:aws:iam::{account}:user/scanner</Arn>
                    <UserId>USER</UserId>
                  </GetCallerIdentityResult>
                </GetCallerIdentityResponse>
            """.encode()
            return AWSResponse(request.url, 200, {}, _Body(body))

        candidate.events.register("before-send.sts.GetCallerIdentity", sts_response)
        return candidate

    monkeypatch.setattr(aws_credential_recovery, "Session", candidate_session)
    recovery = aws_credential_recovery.enable_aws_scan_credential_recovery(
        provider, scan, scanner
    )
    client = session.client("s3")
    if account == current:
        client.list_buckets()
        recovery.raise_if_failed()
    else:
        with pytest.raises(ClientError, match="ExpiredToken"):
            client.list_buckets()
        with pytest.raises(AWSSessionTokenExpiredError):
            recovery.raise_if_failed()

    assert [
        call.kwargs["waiting_for_credentials"]
        for call in scan_query.filter.return_value.update.call_args_list
    ] == [True, False]
