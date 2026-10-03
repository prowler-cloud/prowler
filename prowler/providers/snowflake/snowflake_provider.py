import base64
import hashlib
import os
import re
import time
from urllib.parse import urlparse

import jwt
import requests
from colorama import Fore, Style
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.snowflake.exceptions.exceptions import (
    SnowflakeAuthenticationError,
    SnowflakeCredentialsError,
    SnowflakeIdentityError,
    SnowflakePrivateKeyError,
    SnowflakeSessionError,
)
from prowler.providers.snowflake.lib.mutelist.mutelist import SnowflakeMutelist
from prowler.providers.snowflake.models import (
    SnowflakeIdentityInfo,
    SnowflakeSession,
)

# Snowflake permits key-pair JWTs of up to one hour. Five minutes is used instead: the
# token is minted per request, so a longer life buys nothing, and a token captured from
# a proxy log or a traceback should be expired before anyone reads it.
JWT_TTL_SECONDS = 300

# The SQL API rejects statements that run longer than this, which keeps a pathological
# ACCOUNT_USAGE query from hanging a scan.
STATEMENT_TIMEOUT_SECONDS = 120

REQUEST_TIMEOUT_SECONDS = 60

# The SQL API answers 202 while a statement is still running. These bound the wait so
# a stuck statement fails loudly instead of hanging the scan.
#
# The budget is derived from the statement timeout rather than set independently:
# Snowflake answers 202 at 45 seconds and can keep running until
# STATEMENT_TIMEOUT_SECONDS, so a shorter poll budget would abandon a statement
# that was about to return rows -- reporting a failure where there was none.
POLL_INTERVAL_SECONDS = 2
POLL_MAX_ATTEMPTS = STATEMENT_TIMEOUT_SECONDS // POLL_INTERVAL_SECONDS + 15

SNOWFLAKE_HOST_SUFFIX = ".snowflakecomputing.com"

# Snowflake account identifiers are alphanumeric with hyphens, underscores and dots
# (the legacy locator carries region and cloud segments). Anything else is rejected
# rather than interpolated into the request host.
ACCOUNT_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}")


def _normalize_account(raw: str) -> str:
    """Whatever the user supplied, reduced to a validated account identifier.

    The Snowflake console shows the account in three different forms depending on where
    you look -- as a full URL, with a trailing ``.snowflakecomputing.com``, or on its
    own -- so all three are accepted rather than only the one the documentation happens
    to use.

    The result is interpolated into the request host, so it is validated rather than
    merely trimmed: a value carrying a port, credentials, a query string or a fragment
    would otherwise redirect a signed JWT at a host of the supplier's choosing.

    Args:
        raw: The account identifier, hostname or URL as supplied.

    Returns:
        str: The bare account identifier, e.g. ``myorg-myaccount``.

    Raises:
        SnowflakeCredentialsError: If the value is not a Snowflake account identifier.
    """
    host = raw.strip()
    if "://" in host:
        parsed = urlparse(host)
        if parsed.scheme != "https":
            raise SnowflakeCredentialsError(
                file=os.path.basename(__file__),
                message=(
                    "A Snowflake account URL must use https. Supply the account "
                    "identifier on its own if in doubt."
                ),
            )
        if parsed.username or parsed.password or parsed.port:
            raise SnowflakeCredentialsError(
                file=os.path.basename(__file__),
                message=(
                    "A Snowflake account URL must not carry credentials or a port."
                ),
            )
        if parsed.query or parsed.fragment:
            raise SnowflakeCredentialsError(
                file=os.path.basename(__file__),
                message=(
                    "A Snowflake account URL must not carry a query string or fragment."
                ),
            )
        host = parsed.hostname or ""
    host = host.split("/", 1)[0]

    if host.lower().endswith(SNOWFLAKE_HOST_SUFFIX):
        host = host[: -len(SNOWFLAKE_HOST_SUFFIX)]

    if not ACCOUNT_IDENTIFIER_RE.fullmatch(host):
        raise SnowflakeCredentialsError(
            file=os.path.basename(__file__),
            message=(
                f"'{raw}' is not a Snowflake account identifier. Expected a value like "
                "myorg-myaccount, optionally as a "
                "https://<account>.snowflakecomputing.com URL."
            ),
        )
    return host


def _account_for_claims(account: str) -> str:
    """The account as it must appear in the JWT ``iss`` and ``sub`` claims.

    Uppercased, with any region or cloud segment of a legacy account locator dropped:
    Snowflake keys the JWT on the account alone, so ``ab12345.eu-west-1.aws`` signs as
    ``AB12345``. The newer ``orgname-accountname`` form contains no dot and passes
    through whole.

    Args:
        account: The bare account identifier.

    Returns:
        str: The account as used in the JWT claims.
    """
    return account.split(".")[0].upper()


class SnowflakeSqlApiClient:
    """Minimal Snowflake SQL API client.

    Snowflake's official connector is deliberately not used. It is a large dependency
    with its own transitive tree, and every statement Prowler runs is a read against
    ``SNOWFLAKE.ACCOUNT_USAGE`` -- which the SQL API serves over plain HTTPS. This keeps
    the provider to libraries Prowler already ships.

    Key-pair authentication has no token endpoint: a short-lived RS256 JWT is signed per
    request with the user's private key.
    """

    def __init__(
        self,
        account: str,
        user: str,
        private_key: rsa.RSAPrivateKey,
        role: str = None,
        warehouse: str = None,
    ):
        """Initialize the SQL API client.

        Args:
            account: The bare account identifier.
            user: The Snowflake user to authenticate as.
            private_key: The loaded RSA private key.
            role: Role to use for statements, or None for the user's default.
            warehouse: Warehouse to run statements on, or None for the user's default.
        """
        self.account = account
        self.user = user
        self.private_key = private_key
        self.role = role
        self.warehouse = warehouse
        self.host = f"{account}{SNOWFLAKE_HOST_SUFFIX}"
        self.base_url = f"https://{self.host}"

    def public_key_fingerprint(self) -> str:
        """``SHA256:<base64>`` over the DER-encoded public key.

        This is the exact form Snowflake stores after ``ALTER USER ... SET
        RSA_PUBLIC_KEY`` and reports as ``RSA_PUBLIC_KEY_FP`` in ``DESCRIBE USER``. It
        also forms part of the JWT issuer claim, which is how Snowflake knows which of a
        user's two permitted keys signed a given token.

        Returns:
            str: The public key fingerprint.
        """
        der = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode(
            "ascii"
        )

    def _build_jwt(self) -> str:
        """Sign a short-lived RS256 JWT for the SQL API.

        Returns:
            str: The encoded JWT.
        """
        qualified = f"{_account_for_claims(self.account)}.{self.user.upper()}"
        issued = int(time.time())
        return jwt.encode(
            {
                "iss": f"{qualified}.{self.public_key_fingerprint()}",
                "sub": qualified,
                "iat": issued,
                "exp": issued + JWT_TTL_SECONDS,
            },
            self.private_key,
            algorithm="RS256",
        )

    def _send(self, method: str, url: str, json_body: dict = None):
        """Perform one authenticated SQL API request.

        A fresh JWT is signed per request rather than cached, because the token lives
        five minutes and a long-running scan would otherwise present an expired one.

        Args:
            method: The HTTP method.
            url: The absolute URL to call.
            json_body: The JSON payload, for POST requests.

        Returns:
            requests.Response: The raw response.

        Raises:
            SnowflakeAuthenticationError: If Snowflake rejects the credentials.
            SnowflakeSessionError: If the request fails or Snowflake returns an error.
        """
        try:
            response = requests.request(
                method,
                url,
                json=json_body,
                headers={
                    "Authorization": f"Bearer {self._build_jwt()}",
                    "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as error:
            raise SnowflakeSessionError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

        if response.status_code in (401, 403):
            raise SnowflakeAuthenticationError(
                file=os.path.basename(__file__),
                message=(
                    "Snowflake rejected the key-pair JWT. Confirm the public key is set "
                    f"on user {self.user} and that its fingerprint matches "
                    f"{self.public_key_fingerprint()}."
                ),
            )
        if response.status_code >= 400:
            raise SnowflakeSessionError(
                file=os.path.basename(__file__),
                message=(
                    f"Snowflake returned HTTP {response.status_code} for a statement: "
                    f"{response.text[:200]}"
                ),
            )
        return response

    def _absolute(self, url: str) -> str:
        """Resolve a SQL API path against the account host.

        The returned URL carries a signed JWT, so a value taken from the API response is
        constrained rather than trusted: only https, and only this account's host. An
        `http://` or off-host status URL would otherwise transmit the credential in
        cleartext or to somewhere else entirely.

        Args:
            url: An absolute URL or a path returned by the API.

        Returns:
            str: An absolute URL on the account host.

        Raises:
            SnowflakeSessionError: If the URL is not https on the account host.
        """
        if "://" in url:
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.hostname != self.host:
                raise SnowflakeSessionError(
                    file=os.path.basename(__file__),
                    message=(
                        "Snowflake returned a status URL that is not https on "
                        f"{self.host}. Refusing to send the signed token to it."
                    ),
                )
            return url
        return f"{self.base_url}{url if url.startswith('/') else '/' + url}"

    def _await_result(self, response) -> dict:
        """Resolve an in-progress statement into its completed response body.

        The SQL API answers HTTP 202 when a statement runs longer than 45 seconds,
        returning a status document rather than results. Treating that as success would
        parse the status document as a result set and yield **zero rows with no error**
        -- a large account would silently report nothing found.

        Args:
            response: The response to the initial request.

        Returns:
            dict: The completed response body.

        Raises:
            SnowflakeSessionError: If the statement does not complete in time.
        """
        for _ in range(POLL_MAX_ATTEMPTS):
            if response.status_code != 202:
                return response.json()
            body = response.json()
            status_url = body.get("statementStatusUrl")
            if not status_url:
                handle = body.get("statementHandle")
                if not handle:
                    raise SnowflakeSessionError(
                        file=os.path.basename(__file__),
                        message=(
                            "Snowflake reported a statement as still running but "
                            "returned no way to poll it."
                        ),
                    )
                status_url = f"/api/v2/statements/{handle}"
            time.sleep(POLL_INTERVAL_SECONDS)
            response = self._send("GET", self._absolute(status_url))

        raise SnowflakeSessionError(
            file=os.path.basename(__file__),
            message=(
                "A Snowflake statement did not finish within "
                f"{POLL_MAX_ATTEMPTS * POLL_INTERVAL_SECONDS}s. Reporting the failure "
                "rather than an empty result set."
            ),
        )

    @staticmethod
    def _rows(body: dict, columns: list[str]) -> list[dict]:
        """Zip one response body's rows against the column names.

        Args:
            body: A response body containing a ``data`` array.
            columns: The column names, in order.

        Returns:
            list[dict]: One dictionary per row.
        """
        return [dict(zip(columns, row)) for row in body.get("data") or []]

    def query(self, statement: str) -> list[dict]:
        """Run one read-only statement and return every row as a dictionary.

        Args:
            statement: The SQL statement to execute.

        Returns:
            list[dict]: One dictionary per row, keyed by column name, across every
            partition of the result set.

        Raises:
            SnowflakeAuthenticationError: If Snowflake rejects the credentials.
            SnowflakeSessionError: If the request fails, the statement does not
                complete, or a partition cannot be read.
        """
        payload = {"statement": statement, "timeout": STATEMENT_TIMEOUT_SECONDS}
        if self.role:
            payload["role"] = self.role
        if self.warehouse:
            payload["warehouse"] = self.warehouse

        response = self._send(
            "POST", f"{self.base_url}/api/v2/statements", json_body=payload
        )
        body = self._await_result(response)

        metadata = body.get("resultSetMetaData") or {}
        columns = [column["name"] for column in metadata.get("rowType") or []]
        rows = self._rows(body, columns)

        # A large result set is split into partitions and the initial response carries
        # only the first. Reading `data` alone returns a subset with no error set, which
        # is indistinguishable from a complete read -- so a big account would silently
        # under-report.
        partitions = metadata.get("partitionInfo") or []
        if len(partitions) > 1:
            handle = body.get("statementHandle")
            if not handle:
                raise SnowflakeSessionError(
                    file=os.path.basename(__file__),
                    message=(
                        f"Snowflake split the result across {len(partitions)} "
                        "partitions but returned no statement handle to read them "
                        "with. Reporting the failure rather than a partial result set."
                    ),
                )
            for index in range(1, len(partitions)):
                partition = self._send(
                    "GET",
                    f"{self.base_url}/api/v2/statements/{handle}?partition={index}",
                )
                rows.extend(self._rows(self._await_result(partition), columns))

        return rows


class SnowflakeProvider(Provider):
    """Snowflake provider."""

    _type: str = "snowflake"
    _session: SnowflakeSession
    _identity: SnowflakeIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: SnowflakeMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        config_path: str = None,
        config_content: dict | None = None,
        fixer_config: dict | None = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        account: str = None,
        user: str = None,
        private_key_path: str = None,
        private_key_content: str = None,
        private_key_passphrase: str = None,
        role: str = None,
        warehouse: str = None,
    ):
        """Initializes the SnowflakeProvider instance.

        Args:
            config_path: Path to the configuration file.
            config_content: Audit configuration content.
            fixer_config: Fixer configuration.
            mutelist_path: Path to the mutelist file.
            mutelist_content: Mutelist content.
            account: Snowflake account identifier (falls back to SNOWFLAKE_ACCOUNT).
            user: Snowflake user (falls back to SNOWFLAKE_USER).
            private_key_path: Path to the PEM private key (falls back to
                SNOWFLAKE_PRIVATE_KEY_PATH).
            private_key_content: PEM private key content (falls back to
                SNOWFLAKE_PRIVATE_KEY).
            private_key_passphrase: Passphrase for an encrypted key (falls back to
                SNOWFLAKE_PRIVATE_KEY_PASSPHRASE).
            role: Role to assume (falls back to SNOWFLAKE_ROLE).
            warehouse: Warehouse to use (falls back to SNOWFLAKE_WAREHOUSE).

        Raises:
            SnowflakeCredentialsError: If the account, user or key is missing.
            SnowflakePrivateKeyError: If the key cannot be loaded.
            SnowflakeIdentityError: If identity information cannot be retrieved.
        """
        logger.info("Instantiating Snowflake provider...")

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._session = SnowflakeProvider.setup_session(
            account=account,
            user=user,
            private_key_path=private_key_path,
            private_key_content=private_key_content,
            private_key_passphrase=private_key_passphrase,
            role=role,
            warehouse=warehouse,
        )

        self._identity = SnowflakeProvider.setup_identity(self._session)

        self._fixer_config = fixer_config if fixer_config is not None else {}

        if mutelist_content:
            self._mutelist = SnowflakeMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = SnowflakeMutelist(mutelist_path=mutelist_path)

        Provider.set_global_provider(self)

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def identity(self):
        return self._identity

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> SnowflakeMutelist:
        return self._mutelist

    def validate_arguments(self) -> None:
        """Snowflake provider has no argument combinations to validate."""
        return None

    @staticmethod
    def load_private_key(
        private_key_path: str = None,
        private_key_content: str = None,
        private_key_passphrase: str = None,
    ) -> rsa.RSAPrivateKey:
        """Load the RSA private key used for key-pair authentication.

        Args:
            private_key_path: Path to a PEM file.
            private_key_content: PEM content, used when no path is given.
            private_key_passphrase: Passphrase for an encrypted key.

        Returns:
            rsa.RSAPrivateKey: The loaded private key.

        Raises:
            SnowflakeCredentialsError: If no key material was supplied.
            SnowflakePrivateKeyError: If the key cannot be parsed or is not RSA.
        """
        pem = private_key_content
        if not pem and private_key_path:
            try:
                with open(private_key_path, "r", encoding="utf-8") as key_file:
                    pem = key_file.read()
            except OSError as error:
                raise SnowflakePrivateKeyError(
                    file=os.path.basename(__file__),
                    message=f"The private key file could not be read: {private_key_path}",
                    original_exception=error,
                )
        if not pem:
            raise SnowflakeCredentialsError(
                file=os.path.basename(__file__),
                message=(
                    "No Snowflake private key was supplied. Set "
                    "SNOWFLAKE_PRIVATE_KEY_PATH or SNOWFLAKE_PRIVATE_KEY."
                ),
            )

        password = (
            private_key_passphrase.encode("utf-8") if private_key_passphrase else None
        )
        try:
            key = serialization.load_pem_private_key(
                pem.encode("utf-8"), password=password
            )
        except Exception as error:
            # The underlying message is accurate but unactionable ("Could not
            # deserialize key data"), and the three things that are actually wrong are
            # always the three named here.
            raise SnowflakePrivateKeyError(
                file=os.path.basename(__file__),
                message=(
                    "The private key could not be parsed. Supply the full PEM -- an "
                    "unencrypted PKCS#8 '-----BEGIN PRIVATE KEY-----' block, or an "
                    "encrypted one together with its passphrase."
                ),
                original_exception=error,
            )

        if not isinstance(key, rsa.RSAPrivateKey):
            raise SnowflakePrivateKeyError(
                file=os.path.basename(__file__),
                message=(
                    "Snowflake key-pair authentication requires an RSA key; the supplied "
                    "PEM holds a different key type."
                ),
            )
        return key

    @staticmethod
    def setup_session(
        account: str = None,
        user: str = None,
        private_key_path: str = None,
        private_key_content: str = None,
        private_key_passphrase: str = None,
        role: str = None,
        warehouse: str = None,
    ) -> SnowflakeSession:
        """Build the Snowflake session.

        Credentials may be provided as arguments or read from the environment:
        SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, SNOWFLAKE_PRIVATE_KEY_PATH,
        SNOWFLAKE_PRIVATE_KEY, SNOWFLAKE_PRIVATE_KEY_PASSPHRASE, SNOWFLAKE_ROLE and
        SNOWFLAKE_WAREHOUSE.

        Args:
            account: Account identifier.
            user: Snowflake user.
            private_key_path: Path to the PEM private key.
            private_key_content: PEM private key content.
            private_key_passphrase: Passphrase for an encrypted key.
            role: Role to assume.
            warehouse: Warehouse to use.

        Returns:
            SnowflakeSession: The authenticated session.

        Raises:
            SnowflakeCredentialsError: If the account or user is missing.
        """
        account = account or os.getenv("SNOWFLAKE_ACCOUNT")
        user = user or os.getenv("SNOWFLAKE_USER")
        private_key_path = private_key_path or os.getenv("SNOWFLAKE_PRIVATE_KEY_PATH")
        private_key_content = private_key_content or os.getenv("SNOWFLAKE_PRIVATE_KEY")
        private_key_passphrase = private_key_passphrase or os.getenv(
            "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE"
        )
        role = role or os.getenv("SNOWFLAKE_ROLE")
        warehouse = warehouse or os.getenv("SNOWFLAKE_WAREHOUSE")

        if not account or not user:
            raise SnowflakeCredentialsError(
                file=os.path.basename(__file__),
                message=(
                    "Snowflake needs both an account and a user. Set SNOWFLAKE_ACCOUNT "
                    "and SNOWFLAKE_USER, or pass --account and --user."
                ),
            )

        account = _normalize_account(account)
        private_key = SnowflakeProvider.load_private_key(
            private_key_path=private_key_path,
            private_key_content=private_key_content,
            private_key_passphrase=private_key_passphrase,
        )

        client = SnowflakeSqlApiClient(
            account=account,
            user=user,
            private_key=private_key,
            role=role,
            warehouse=warehouse,
        )
        return SnowflakeSession(
            account=account,
            user=user,
            client=client,
            role=role,
            warehouse=warehouse,
        )

    @staticmethod
    def setup_identity(session: SnowflakeSession) -> SnowflakeIdentityInfo:
        """Retrieve the account context the scan is running under.

        The session context is read from Snowflake rather than echoed back from the
        supplied arguments. The account identifier used in every finding therefore comes
        from the account itself, and a credential that authenticates against a different
        account than intended is visible rather than silent.

        Args:
            session: The Snowflake session.

        Returns:
            SnowflakeIdentityInfo: The identity information.

        Raises:
            SnowflakeIdentityError: If the session context cannot be read.
        """
        try:
            rows = session.client.query(
                "SELECT CURRENT_ACCOUNT() AS ACCOUNT, CURRENT_REGION() AS REGION, "
                "CURRENT_USER() AS USER, CURRENT_ROLE() AS ROLE, "
                "CURRENT_WAREHOUSE() AS WAREHOUSE"
            )
            context = rows[0] if rows else {}
            return SnowflakeIdentityInfo(
                account=session.account,
                account_locator=context.get("ACCOUNT"),
                region=context.get("REGION"),
                user=context.get("USER") or session.user,
                role=context.get("ROLE") or session.role,
                warehouse=context.get("WAREHOUSE") or session.warehouse,
            )
        except (SnowflakeAuthenticationError, SnowflakeSessionError):
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise SnowflakeIdentityError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def print_credentials(self) -> None:
        report_title = (
            f"{Style.BRIGHT}Using the Snowflake credentials below:{Style.RESET_ALL}"
        )
        report_lines = [
            f"Authentication: {Fore.YELLOW}Key-pair (RSA){Style.RESET_ALL}",
            f"Account: {Fore.YELLOW}{self.identity.account}{Style.RESET_ALL}",
        ]
        if self.identity.account_locator:
            report_lines.append(
                f"Account Locator: {Fore.YELLOW}{self.identity.account_locator}{Style.RESET_ALL}"
            )
        if self.identity.region:
            report_lines.append(
                f"Region: {Fore.YELLOW}{self.identity.region}{Style.RESET_ALL}"
            )
        if self.identity.user:
            report_lines.append(
                f"User: {Fore.YELLOW}{self.identity.user}{Style.RESET_ALL}"
            )
        if self.identity.role:
            report_lines.append(
                f"Role: {Fore.YELLOW}{self.identity.role}{Style.RESET_ALL}"
            )
        if self.identity.warehouse:
            report_lines.append(
                f"Warehouse: {Fore.YELLOW}{self.identity.warehouse}{Style.RESET_ALL}"
            )

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        account: str = None,
        user: str = None,
        private_key_path: str = None,
        private_key_content: str = None,
        private_key_passphrase: str = None,
        role: str = None,
        warehouse: str = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        """Test the connection to Snowflake.

        Args:
            account: Account identifier.
            user: Snowflake user.
            private_key_path: Path to the PEM private key.
            private_key_content: PEM private key content.
            private_key_passphrase: Passphrase for an encrypted key.
            role: Role to assume.
            warehouse: Warehouse to use.
            raise_on_exception: Whether to raise if the connection fails.

        Returns:
            Connection: Connection object with the is_connected status.
        """
        try:
            session = SnowflakeProvider.setup_session(
                account=account,
                user=user,
                private_key_path=private_key_path,
                private_key_content=private_key_content,
                private_key_passphrase=private_key_passphrase,
                role=role,
                warehouse=warehouse,
            )
            session.client.query("SELECT CURRENT_ACCOUNT() AS ACCOUNT")
            return Connection(is_connected=True)
        except (
            SnowflakeCredentialsError,
            SnowflakePrivateKeyError,
            SnowflakeAuthenticationError,
        ) as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise
            return Connection(is_connected=False, error=error)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise SnowflakeSessionError(
                    file=os.path.basename(__file__),
                    original_exception=error,
                )
            return Connection(is_connected=False, error=error)
