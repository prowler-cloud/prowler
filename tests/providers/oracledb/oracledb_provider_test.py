from unittest import mock
from unittest.mock import MagicMock, patch

import oracledb
import pytest

from prowler.providers.common.models import Connection
from prowler.providers.oracledb.exceptions.exceptions import (
    OracledbConnectionError,
    OracledbEnvironmentVariableError,
    OracledbInvalidCredentialsError,
    OracledbInvalidProviderIdError,
    OracledbSetUpIdentityError,
)
from prowler.providers.oracledb.models import OracledbIdentityInfo, OracledbSession
from prowler.providers.oracledb.oracledb_provider import OracledbProvider
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    ORACLEDB_DSN,
    ORACLEDB_PASSWORD,
    ORACLEDB_USER,
    ORACLEDB_VERSION,
    set_mocked_connection,
)

PROVIDER_PATH = "prowler.providers.oracledb.oracledb_provider"


class TestOracledbProvider:
    def test_validate_arguments_missing_all(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with pytest.raises(OracledbEnvironmentVariableError) as exception:
                OracledbProvider.validate_arguments()
            assert "--oracledb-user / ORACLEDB_USER" in str(exception.value)
            assert "ORACLEDB_PASSWORD" in str(exception.value)
            assert "--oracledb-dsn / ORACLEDB_DSN" in str(exception.value)

    def test_validate_arguments_missing_password(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with pytest.raises(OracledbEnvironmentVariableError) as exception:
                OracledbProvider.validate_arguments(
                    oracledb_user=ORACLEDB_USER,
                    oracledb_dsn=ORACLEDB_DSN,
                )
            assert "ORACLEDB_PASSWORD" in str(exception.value)
            assert "--oracledb-user" not in str(exception.value)

    def test_validate_arguments_from_environment(self):
        environment = {
            "ORACLEDB_USER": ORACLEDB_USER,
            "ORACLEDB_PASSWORD": ORACLEDB_PASSWORD,
            "ORACLEDB_DSN": ORACLEDB_DSN,
        }
        with mock.patch.dict("os.environ", environment, clear=True):
            assert OracledbProvider.validate_arguments() is None

    def test_resolve_dsn_explicit_dsn_wins(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            assert (
                OracledbProvider.resolve_dsn(
                    dsn=ORACLEDB_DSN, host="other", service_name="OTHER"
                )
                == ORACLEDB_DSN
            )

    def test_resolve_dsn_from_host_port_service(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            assert (
                OracledbProvider.resolve_dsn(
                    host="dbhost.example.com",
                    port=1522,
                    service_name="ORCLPDB1",
                )
                == "dbhost.example.com:1522/ORCLPDB1"
            )

    def test_resolve_dsn_default_port(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            assert (
                OracledbProvider.resolve_dsn(
                    host="dbhost.example.com", service_name="ORCLPDB1"
                )
                == "dbhost.example.com:1521/ORCLPDB1"
            )

    def test_resolve_dsn_empty_when_incomplete(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            assert OracledbProvider.resolve_dsn(host="dbhost.example.com") == ""

    def test_setup_session_success(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            connection = MagicMock()
            with patch(
                f"{PROVIDER_PATH}.oracledb.connect", return_value=connection
            ) as mock_connect:
                session = OracledbProvider.setup_session(
                    user=ORACLEDB_USER,
                    password=ORACLEDB_PASSWORD,
                    dsn=ORACLEDB_DSN,
                )
            mock_connect.assert_called_once_with(
                user=ORACLEDB_USER, password=ORACLEDB_PASSWORD, dsn=ORACLEDB_DSN
            )
            assert isinstance(session, OracledbSession)
            assert session.user == ORACLEDB_USER
            assert session.dsn == ORACLEDB_DSN
            assert session.connection is connection

    def test_setup_session_invalid_credentials(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with patch(
                f"{PROVIDER_PATH}.oracledb.connect",
                side_effect=oracledb.DatabaseError(
                    "ORA-01017: invalid username/password; logon denied"
                ),
            ):
                with pytest.raises(OracledbInvalidCredentialsError):
                    OracledbProvider.setup_session(
                        user=ORACLEDB_USER,
                        password="wrong",
                        dsn=ORACLEDB_DSN,
                    )

    def test_setup_session_connection_error(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with patch(
                f"{PROVIDER_PATH}.oracledb.connect",
                side_effect=oracledb.DatabaseError(
                    "DPY-6001: cannot connect to database"
                ),
            ):
                with pytest.raises(OracledbConnectionError):
                    OracledbProvider.setup_session(
                        user=ORACLEDB_USER,
                        password=ORACLEDB_PASSWORD,
                        dsn=ORACLEDB_DSN,
                    )

    def test_setup_identity(self):
        connection = set_mocked_connection(
            fetchone_results=[(ORACLEDB_DATABASE_NAME,), (ORACLEDB_VERSION,)]
        )
        session = OracledbSession(
            user=ORACLEDB_USER, dsn=ORACLEDB_DSN, connection=connection
        )

        identity = OracledbProvider.setup_identity(session)

        assert isinstance(identity, OracledbIdentityInfo)
        assert identity.user == ORACLEDB_USER
        assert identity.dsn == ORACLEDB_DSN
        assert identity.database_name == ORACLEDB_DATABASE_NAME
        assert identity.version == ORACLEDB_VERSION

    def test_setup_identity_version_unreadable(self):
        connection = MagicMock()
        cursor = MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchone.return_value = (ORACLEDB_DATABASE_NAME,)
        cursor.execute.side_effect = [
            None,
            oracledb.DatabaseError("ORA-00942: table or view does not exist"),
        ]
        session = OracledbSession(
            user=ORACLEDB_USER, dsn=ORACLEDB_DSN, connection=connection
        )

        identity = OracledbProvider.setup_identity(session)

        assert identity.database_name == ORACLEDB_DATABASE_NAME
        assert identity.version == ""

    def test_setup_identity_error(self):
        connection = MagicMock()
        connection.cursor.side_effect = oracledb.DatabaseError(
            "ORA-01034: ORACLE not available"
        )
        session = OracledbSession(
            user=ORACLEDB_USER, dsn=ORACLEDB_DSN, connection=connection
        )

        with pytest.raises(OracledbSetUpIdentityError):
            OracledbProvider.setup_identity(session)

    def test_provider_init(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            connection = set_mocked_connection(
                fetchone_results=[(ORACLEDB_DATABASE_NAME,), (ORACLEDB_VERSION,)]
            )
            with patch(f"{PROVIDER_PATH}.oracledb.connect", return_value=connection):
                provider = OracledbProvider(
                    oracledb_user=ORACLEDB_USER,
                    oracledb_password=ORACLEDB_PASSWORD,
                    oracledb_dsn=ORACLEDB_DSN,
                )

            assert provider.type == "oracledb"
            assert provider.auth_method == "User / Password"
            assert provider.session.user == ORACLEDB_USER
            assert provider.identity.database_name == ORACLEDB_DATABASE_NAME
            assert provider.audit_config == {}
            assert provider.mutelist.mutelist == {}

    def test_test_connection_success(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            connection = set_mocked_connection(
                fetchone_results=[(ORACLEDB_DATABASE_NAME,), (ORACLEDB_VERSION,)]
            )
            with patch(f"{PROVIDER_PATH}.oracledb.connect", return_value=connection):
                result = OracledbProvider.test_connection(
                    oracledb_user=ORACLEDB_USER,
                    oracledb_password=ORACLEDB_PASSWORD,
                    oracledb_dsn=ORACLEDB_DSN,
                )

            assert isinstance(result, Connection)
            assert result.is_connected is True
            connection.close.assert_called_once()

    def test_test_connection_provider_id_match(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            connection = set_mocked_connection(
                fetchone_results=[(ORACLEDB_DATABASE_NAME,), (ORACLEDB_VERSION,)]
            )
            with patch(f"{PROVIDER_PATH}.oracledb.connect", return_value=connection):
                result = OracledbProvider.test_connection(
                    oracledb_user=ORACLEDB_USER,
                    oracledb_password=ORACLEDB_PASSWORD,
                    oracledb_dsn=ORACLEDB_DSN,
                    provider_id=ORACLEDB_DATABASE_NAME.lower(),
                )

            assert result.is_connected is True

    def test_test_connection_provider_id_mismatch(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            connection = set_mocked_connection(
                fetchone_results=[(ORACLEDB_DATABASE_NAME,), (ORACLEDB_VERSION,)]
            )
            with patch(f"{PROVIDER_PATH}.oracledb.connect", return_value=connection):
                with pytest.raises(OracledbInvalidProviderIdError):
                    OracledbProvider.test_connection(
                        oracledb_user=ORACLEDB_USER,
                        oracledb_password=ORACLEDB_PASSWORD,
                        oracledb_dsn=ORACLEDB_DSN,
                        provider_id="OTHERDB.EXAMPLE.COM",
                    )

    def test_test_connection_no_raise(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            result = OracledbProvider.test_connection(raise_on_exception=False)

            assert result.is_connected is False
            assert isinstance(result.error, OracledbEnvironmentVariableError)
