import os
from unittest import mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from prowler.providers.snowflake.exceptions.exceptions import (
    SnowflakeAuthenticationError,
    SnowflakeCredentialsError,
    SnowflakeIdentityError,
    SnowflakePrivateKeyError,
    SnowflakeSessionError,
)
from prowler.providers.snowflake.models import SnowflakeIdentityInfo, SnowflakeSession
from prowler.providers.snowflake.snowflake_provider import (
    SnowflakeProvider,
    SnowflakeSqlApiClient,
    _account_for_claims,
    _normalize_account,
)
from tests.providers.snowflake.snowflake_fixtures import (
    ACCOUNT,
    ACCOUNT_LOCATOR,
    REGION,
    ROLE,
    USER,
    WAREHOUSE,
    generate_private_key_pem,
)

SNOWFLAKE_ENV_VARS = (
    "SNOWFLAKE_ACCOUNT",
    "SNOWFLAKE_USER",
    "SNOWFLAKE_PRIVATE_KEY",
    "SNOWFLAKE_PRIVATE_KEY_PATH",
    "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE",
    "SNOWFLAKE_ROLE",
    "SNOWFLAKE_WAREHOUSE",
)


@pytest.fixture(autouse=True)
def clear_snowflake_env():
    """Keep a developer's real Snowflake environment out of these tests."""
    with mock.patch.dict(os.environ, {}, clear=False):
        for name in SNOWFLAKE_ENV_VARS:
            os.environ.pop(name, None)
        yield


class TestNormalizeAccount:
    @pytest.mark.parametrize(
        "supplied",
        [
            "myorg-myaccount",
            "myorg-myaccount.snowflakecomputing.com",
            "https://myorg-myaccount.snowflakecomputing.com",
            "https://myorg-myaccount.snowflakecomputing.com/console",
            "  myorg-myaccount  ",
        ],
    )
    def test_every_form_the_console_shows_reduces_to_the_identifier(self, supplied):
        assert _normalize_account(supplied) == "myorg-myaccount"


class TestNormalizeAccountRejectsUnsafeValues:
    # The account is interpolated into the request host and a signed JWT is sent there,
    # so a value carrying a port, credentials, a query or a fragment must be refused
    # rather than trimmed.
    @pytest.mark.parametrize(
        "supplied",
        [
            "myacct?redirect=evil.test",
            "myacct#fragment",
            "https://evil.test:8443",
            "https://user:pw@myacct.snowflakecomputing.com",
            "http://myacct.snowflakecomputing.com",
            "my acct",
            "",
        ],
    )
    def test_unsafe_values_are_rejected(self, supplied):
        with pytest.raises(SnowflakeCredentialsError):
            _normalize_account(supplied)


class TestAccountForClaims:
    def test_identifier_is_uppercased(self):
        assert _account_for_claims("myorg-myaccount") == "MYORG-MYACCOUNT"

    def test_legacy_locator_drops_the_region_and_cloud_segments(self):
        # Snowflake keys the JWT on the account alone. Leaving the region on produces a
        # token the account rejects, which surfaces as an unhelpful 401.
        assert _account_for_claims("ab12345.eu-west-1.aws") == "AB12345"


class TestSnowflakeProviderLoadPrivateKey:
    def test_loads_an_unencrypted_key_from_content(self):
        key = SnowflakeProvider.load_private_key(
            private_key_content=generate_private_key_pem()
        )
        assert key.key_size == 2048

    def test_loads_an_encrypted_key_with_its_passphrase(self):
        pem = generate_private_key_pem(passphrase="correct horse")
        key = SnowflakeProvider.load_private_key(
            private_key_content=pem, private_key_passphrase="correct horse"
        )
        assert key.key_size == 2048

    def test_encrypted_key_without_passphrase_raises(self):
        pem = generate_private_key_pem(passphrase="correct horse")
        with pytest.raises(SnowflakePrivateKeyError):
            SnowflakeProvider.load_private_key(private_key_content=pem)

    def test_loads_from_a_path(self, tmp_path):
        key_file = tmp_path / "rsa_key.p8"
        key_file.write_text(generate_private_key_pem())
        key = SnowflakeProvider.load_private_key(private_key_path=str(key_file))
        assert key.key_size == 2048

    def test_unreadable_path_raises_private_key_error(self, tmp_path):
        with pytest.raises(SnowflakePrivateKeyError):
            SnowflakeProvider.load_private_key(
                private_key_path=str(tmp_path / "absent.p8")
            )

    def test_no_key_material_raises_credentials_error(self):
        with pytest.raises(SnowflakeCredentialsError):
            SnowflakeProvider.load_private_key()

    def test_a_non_rsa_key_is_rejected(self):
        # Snowflake key-pair auth is RSA only, and the failure is otherwise a 401 at
        # scan time rather than a clear error at setup.
        from cryptography.hazmat.primitives import serialization

        pem = (
            ed25519.Ed25519PrivateKey.generate()
            .private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode()
        )
        with pytest.raises(SnowflakePrivateKeyError):
            SnowflakeProvider.load_private_key(private_key_content=pem)


class TestSnowflakeProviderSetupSession:
    def test_missing_account_and_user_raises_credentials_error(self):
        with pytest.raises(SnowflakeCredentialsError):
            SnowflakeProvider.setup_session(
                private_key_content=generate_private_key_pem()
            )

    def test_builds_a_session_from_arguments(self):
        session = SnowflakeProvider.setup_session(
            account=ACCOUNT,
            user=USER,
            private_key_content=generate_private_key_pem(),
            role=ROLE,
            warehouse=WAREHOUSE,
        )
        assert isinstance(session, SnowflakeSession)
        assert session.account == ACCOUNT
        assert session.user == USER
        assert session.role == ROLE
        assert session.warehouse == WAREHOUSE
        assert isinstance(session.client, SnowflakeSqlApiClient)

    def test_reads_credentials_from_the_environment(self):
        os.environ["SNOWFLAKE_ACCOUNT"] = ACCOUNT
        os.environ["SNOWFLAKE_USER"] = USER
        os.environ["SNOWFLAKE_PRIVATE_KEY"] = generate_private_key_pem()
        os.environ["SNOWFLAKE_ROLE"] = ROLE
        session = SnowflakeProvider.setup_session()
        assert session.account == ACCOUNT
        assert session.role == ROLE

    def test_a_session_never_prints_the_key(self):
        # The client holds the private key, and pydantic prints every field by default,
        # so an unguarded session in a traceback would publish the whole credential.
        session = SnowflakeProvider.setup_session(
            account=ACCOUNT,
            user=USER,
            private_key_content=generate_private_key_pem(),
        )
        assert "PRIVATE KEY" not in repr(session)
        assert "PRIVATE KEY" not in str(session)
        assert "client=***" in repr(session)


class TestSnowflakeSqlApiClient:
    def _client(self):
        return SnowflakeSqlApiClient(
            account=ACCOUNT,
            user=USER,
            private_key=SnowflakeProvider.load_private_key(
                private_key_content=generate_private_key_pem()
            ),
            role=ROLE,
            warehouse=WAREHOUSE,
        )

    def test_fingerprint_has_the_form_snowflake_reports(self):
        # Snowflake shows this as RSA_PUBLIC_KEY_FP in DESCRIBE USER; comparing the two
        # is how a failed first connection is diagnosed.
        fingerprint = self._client().public_key_fingerprint()
        assert fingerprint.startswith("SHA256:")
        assert len(fingerprint) > len("SHA256:")

    def test_jwt_claims_carry_the_account_user_and_fingerprint(self):
        client = self._client()
        token = client._build_jwt()
        claims = jwt.decode(token, options={"verify_signature": False})
        qualified = f"{ACCOUNT.upper()}.{USER.upper()}"
        assert claims["sub"] == qualified
        assert claims["iss"] == f"{qualified}.{client.public_key_fingerprint()}"
        assert claims["exp"] > claims["iat"]

    def test_rows_are_keyed_by_column_name(self):
        client = self._client()
        response = mock.MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "resultSetMetaData": {"rowType": [{"name": "NAME"}, {"name": "DISABLED"}]},
            "data": [["ALICE", "false"], ["BOB", "true"]],
        }
        with mock.patch(
            "prowler.providers.snowflake.snowflake_provider.requests.request",
            return_value=response,
        ):
            rows = client.query("SELECT 1")
        assert rows == [
            {"NAME": "ALICE", "DISABLED": "false"},
            {"NAME": "BOB", "DISABLED": "true"},
        ]

    @pytest.mark.parametrize("status_code", [401, 403])
    def test_rejected_credentials_raise_an_authentication_error(self, status_code):
        response = mock.MagicMock()
        response.status_code = status_code
        with mock.patch(
            "prowler.providers.snowflake.snowflake_provider.requests.request",
            return_value=response,
        ):
            with pytest.raises(SnowflakeAuthenticationError):
                self._client().query("SELECT 1")

    def test_other_http_errors_raise_a_session_error(self):
        response = mock.MagicMock()
        response.status_code = 500
        response.text = "internal error"
        with mock.patch(
            "prowler.providers.snowflake.snowflake_provider.requests.request",
            return_value=response,
        ):
            with pytest.raises(SnowflakeSessionError):
                self._client().query("SELECT 1")


class TestSnowflakeProviderSetupIdentity:
    def _session(self):
        return SnowflakeSession(
            account=ACCOUNT, user=USER, client=mock.MagicMock(), role=ROLE
        )

    def test_identity_comes_from_the_account_not_the_arguments(self):
        # The account is read back from Snowflake so a credential that authenticates
        # against a different account than intended is visible rather than silent.
        session = self._session()
        session.client.query.return_value = [
            {
                "ACCOUNT": ACCOUNT_LOCATOR,
                "REGION": REGION,
                "USER": USER,
                "ROLE": ROLE,
                "WAREHOUSE": WAREHOUSE,
            }
        ]
        identity = SnowflakeProvider.setup_identity(session)
        assert isinstance(identity, SnowflakeIdentityInfo)
        assert identity.account == ACCOUNT
        assert identity.account_locator == ACCOUNT_LOCATOR
        assert identity.region == REGION
        assert identity.warehouse == WAREHOUSE

    def test_an_empty_context_falls_back_to_the_session(self):
        session = self._session()
        session.client.query.return_value = []
        identity = SnowflakeProvider.setup_identity(session)
        assert identity.user == USER
        assert identity.role == ROLE

    def test_authentication_errors_are_not_masked_as_identity_errors(self):
        session = self._session()
        session.client.query.side_effect = SnowflakeAuthenticationError(file=__file__)
        with pytest.raises(SnowflakeAuthenticationError):
            SnowflakeProvider.setup_identity(session)

    def test_unexpected_failures_raise_an_identity_error(self):
        session = self._session()
        session.client.query.side_effect = ValueError("unexpected")
        with pytest.raises(SnowflakeIdentityError):
            SnowflakeProvider.setup_identity(session)


class TestSnowflakeProviderTestConnection:
    def test_a_working_credential_reports_connected(self):
        with mock.patch.object(
            SnowflakeSqlApiClient, "query", return_value=[{"ACCOUNT": ACCOUNT_LOCATOR}]
        ):
            connection = SnowflakeProvider.test_connection(
                account=ACCOUNT,
                user=USER,
                private_key_content=generate_private_key_pem(),
            )
        assert connection.is_connected is True

    def test_missing_credentials_can_be_reported_instead_of_raised(self):
        connection = SnowflakeProvider.test_connection(raise_on_exception=False)
        assert connection.is_connected is False
        assert connection.error is not None

    def test_missing_credentials_raise_by_default(self):
        with pytest.raises(SnowflakeCredentialsError):
            SnowflakeProvider.test_connection()


class TestSnowflakeSqlApiClientAsyncAndPartitions:
    def _client(self):
        return SnowflakeSqlApiClient(
            account=ACCOUNT,
            user=USER,
            private_key=SnowflakeProvider.load_private_key(
                private_key_content=generate_private_key_pem()
            ),
        )

    @staticmethod
    def _response(status_code, body):
        response = mock.MagicMock()
        response.status_code = status_code
        response.json.return_value = body
        return response

    def test_a_202_is_polled_until_the_statement_completes(self):
        # The SQL API answers 202 while a statement is still running. Parsing that body
        # as a result set would return zero rows with no error -- a large account
        # silently reporting nothing found.
        running = self._response(
            202,
            {"statementHandle": "h1", "statementStatusUrl": "/api/v2/statements/h1"},
        )
        done = self._response(
            200,
            {
                "resultSetMetaData": {"rowType": [{"name": "NAME"}]},
                "data": [["ALICE"]],
            },
        )
        with (
            mock.patch(
                "prowler.providers.snowflake.snowflake_provider.requests.request",
                side_effect=[running, done],
            ),
            mock.patch("prowler.providers.snowflake.snowflake_provider.time.sleep"),
        ):
            rows = self._client().query("SELECT 1")
        assert rows == [{"NAME": "ALICE"}]

    def test_a_statement_that_never_completes_raises_instead_of_returning_nothing(self):
        running = self._response(
            202,
            {"statementHandle": "h1", "statementStatusUrl": "/api/v2/statements/h1"},
        )
        with (
            mock.patch(
                "prowler.providers.snowflake.snowflake_provider.requests.request",
                return_value=running,
            ),
            mock.patch("prowler.providers.snowflake.snowflake_provider.time.sleep"),
        ):
            with pytest.raises(SnowflakeSessionError):
                self._client().query("SELECT 1")

    def test_every_partition_is_read(self):
        # A large result set is split across partitions and the first response carries
        # only partition 0. Returning it alone is a subset with no error set, which is
        # indistinguishable from a complete read.
        first = self._response(
            200,
            {
                "statementHandle": "h1",
                "resultSetMetaData": {
                    "rowType": [{"name": "NAME"}],
                    "partitionInfo": [
                        {"rowCount": 1},
                        {"rowCount": 1},
                        {"rowCount": 1},
                    ],
                },
                "data": [["ALICE"]],
            },
        )
        second = self._response(200, {"data": [["BOB"]]})
        third = self._response(200, {"data": [["CAROL"]]})
        with mock.patch(
            "prowler.providers.snowflake.snowflake_provider.requests.request",
            side_effect=[first, second, third],
        ):
            rows = self._client().query("SELECT 1")
        assert rows == [{"NAME": "ALICE"}, {"NAME": "BOB"}, {"NAME": "CAROL"}]

    def test_partitions_without_a_handle_raise_rather_than_truncate(self):
        first = self._response(
            200,
            {
                "resultSetMetaData": {
                    "rowType": [{"name": "NAME"}],
                    "partitionInfo": [{"rowCount": 1}, {"rowCount": 1}],
                },
                "data": [["ALICE"]],
            },
        )
        with mock.patch(
            "prowler.providers.snowflake.snowflake_provider.requests.request",
            return_value=first,
        ):
            with pytest.raises(SnowflakeSessionError):
                self._client().query("SELECT 1")

    def test_a_single_partition_needs_no_extra_request(self):
        only = self._response(
            200,
            {
                "statementHandle": "h1",
                "resultSetMetaData": {
                    "rowType": [{"name": "NAME"}],
                    "partitionInfo": [{"rowCount": 1}],
                },
                "data": [["ALICE"]],
            },
        )
        with mock.patch(
            "prowler.providers.snowflake.snowflake_provider.requests.request",
            return_value=only,
        ) as request:
            rows = self._client().query("SELECT 1")
        assert rows == [{"NAME": "ALICE"}]
        assert request.call_count == 1


class TestSnowflakeSessionNeverSerializesTheKey:
    def test_the_client_is_excluded_from_every_serialization_path(self):
        # __repr__ alone is not enough: an output pipeline reaches for model_dump() and
        # model_dump_json() long before anyone prints the object, and the client holds
        # the RSA private key.
        session = SnowflakeProvider.setup_session(
            account=ACCOUNT,
            user=USER,
            private_key_content=generate_private_key_pem(),
        )
        assert "client" not in session.model_dump()
        assert "client" not in session.model_dump_json()
        assert "client" not in dict(session)
        assert "client=***" in repr(session)
