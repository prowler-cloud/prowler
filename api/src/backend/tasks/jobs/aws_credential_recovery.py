from collections.abc import Callable
from contextlib import closing
from threading import Lock
from time import monotonic, sleep

from api.db_utils import rls_transaction
from api.exceptions import ProviderDeletedException
from api.models import Provider, ProviderSecret, Scan
from api.utils import declared_provider_secret
from boto3.session import Session
from botocore.config import Config
from botocore.credentials import Credentials, ReadOnlyCredentials
from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from prowler.providers.aws.aws_provider import AwsProvider, get_aws_region_for_sts
from prowler.providers.aws.exceptions.exceptions import AWSSessionTokenExpiredError

WAIT_SECONDS = 600
IDENTITY_CHECK_CONFIG = Config(
    connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 1}
)


# These are authentication failures, so AWS rejected the original request
# before running the operation. Ordinary permission denials are not retryable.
_CREDENTIAL_ERRORS = frozenset(
    {
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidClientTokenId",
        "InvalidAccessKeyId",
        "UnrecognizedClientException",
    }
)
_SIGNED_GENERATION = "prowler_signed_credential_generation"
_RETRIED = "prowler_retried_credentials"


class _ScanCredentials(Credentials):
    """Share an atomic credential snapshot across clients created for this scan."""

    def __init__(self, credentials: ReadOnlyCredentials) -> None:
        super().__init__(
            credentials.access_key, credentials.secret_key, credentials.token
        )
        self.snapshot = credentials

    def get_frozen_credentials(self) -> ReadOnlyCredentials:
        return self.snapshot


class CredentialRecovery:
    """Retry an AWS authentication failure after an operator replaces credentials.

    A single thread waits for replacement credentials. Other affected requests
    share the result and can retry once. The loader must validate that the
    replacement belongs to the scan's original AWS principal.
    """

    def __init__(
        self,
        session: Session,
        load_replacement: Callable[[ReadOnlyCredentials], ReadOnlyCredentials | None],
        set_waiting: Callable[[bool], None],
        wait_seconds: float,
        poll_seconds: float = 5,
    ) -> None:
        self._credentials = _ScanCredentials(
            session.get_credentials().get_frozen_credentials()
        )
        session._session._credentials = self._credentials
        self._load_replacement = load_replacement
        self._set_waiting = set_waiting
        self._wait_seconds = wait_seconds
        self._poll_seconds = poll_seconds
        self._generation = 0
        self._closed = False
        self._lock = Lock()
        session.events.register("before-sign.*.*", self._record_generation)
        session.events.register_first("needs-retry.*.*", self._retry_with_replacement)

    def _record_generation(self, request, **kwargs) -> None:
        request.context[_SIGNED_GENERATION] = self._generation

    def _retry_with_replacement(self, response, request_dict, **kwargs) -> int | None:
        if (
            response is None
            or response[1].get("Error", {}).get("Code") not in _CREDENTIAL_ERRORS
        ):
            return None

        context = request_dict["context"]
        with self._lock:
            if self._closed:
                return None
            if context.get(_SIGNED_GENERATION) != self._generation:
                return 0
            if context.get(_RETRIED):
                self._closed = True
                return None

            context[_RETRIED] = True
            waiting = False
            try:
                self._set_waiting(True)
                waiting = True
                deadline = monotonic() + self._wait_seconds
                while True:
                    replacement = self._load_replacement(self._credentials.snapshot)
                    if replacement is not None:
                        self._credentials.snapshot = replacement
                        self._generation += 1
                        return 0

                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        self._closed = True
                        return None
                    sleep(min(remaining, self._poll_seconds))
            except Exception:
                # The provider or scan may have been removed while we waited.
                self._closed = True
                raise
            finally:
                if waiting:
                    self._set_waiting(False)

    def raise_if_failed(self) -> None:
        """Keep the runner from treating a rejected request as completed work."""
        if self._closed:
            raise AWSSessionTokenExpiredError(
                message="AWS rejected the scan credentials and no valid replacement was available."
            )


def _principal(account: str, arn: str, user_id: str) -> tuple[str, str, str]:
    """Return the stable principal even when an STS role session name changes."""
    if ":assumed-role/" in arn:
        arn = arn.rsplit("/", 1)[0]
        user_id = user_id.split(":", 1)[0]
    return account, arn, user_id


def enable_aws_scan_credential_recovery(
    provider: Provider, scan: Scan, scanner: AwsProvider
) -> CredentialRecovery | None:
    """Let an AWS scan retry a rejected request after its stored keys are replaced."""
    original_secret = getattr(provider, "secret", None)
    if (
        not original_secret
        or original_secret.secret_type != ProviderSecret.TypeChoices.STATIC
    ):
        return None

    tenant_id, provider_id, scan_id = provider.tenant_id, provider.id, scan.id
    session = scanner.session.current_session
    if session.get_credentials().method != "explicit":
        return None

    identity = scanner.identity
    expected = _principal(identity.account, identity.identity_arn, identity.user_id)
    region = get_aws_region_for_sts(session.region_name, identity.audited_regions)

    def load_replacement(current: ReadOnlyCredentials) -> ReadOnlyCredentials | None:
        with rls_transaction(tenant_id):
            fresh_provider = (
                Provider.objects.select_related("secret").filter(pk=provider_id).first()
            )
            if fresh_provider is None:
                raise ProviderDeletedException("Provider was deleted during the scan")
            if (
                not hasattr(fresh_provider, "secret")
                or fresh_provider.secret.secret_type
                != ProviderSecret.TypeChoices.STATIC
            ):
                return None
            secret = declared_provider_secret(fresh_provider)

        key = secret.get("aws_access_key_id")
        secret_key = secret.get("aws_secret_access_key")
        token = secret.get("aws_session_token")
        if (
            not key
            or not secret_key
            or (key, secret_key, token)
            == (current.access_key, current.secret_key, current.token)
        ):
            return None

        candidate = Session(
            aws_access_key_id=key,
            aws_secret_access_key=secret_key,
            aws_session_token=token,
            region_name=region,
        )
        try:
            with closing(candidate.client("sts", config=IDENTITY_CHECK_CONFIG)) as sts:
                caller = sts.get_caller_identity()
        except (
            ClientError,
            ConnectTimeoutError,
            EndpointConnectionError,
            ReadTimeoutError,
        ):
            return None
        if _principal(caller["Account"], caller["Arn"], caller["UserId"]) != expected:
            return None
        return candidate.get_credentials().get_frozen_credentials()

    def set_waiting(waiting: bool) -> None:
        with rls_transaction(tenant_id):
            updated = Scan.objects.filter(pk=scan_id).update(
                waiting_for_credentials=waiting,
            )
            if not updated:
                raise ProviderDeletedException("Provider was deleted during the scan")

    return CredentialRecovery(session, load_replacement, set_waiting, WAIT_SECONDS)
