from unittest.mock import MagicMock

from prowler.providers.oracledb.models import OracledbIdentityInfo, OracledbSession

ORACLEDB_USER = "PROWLER"
ORACLEDB_PASSWORD = "mock_password"  # nosec B105 - test fixture only
ORACLEDB_DSN = "dbhost.example.com:1521/ORCLPDB1"
ORACLEDB_DATABASE_NAME = "ORCL.EXAMPLE.COM"
ORACLEDB_VERSION = "19.21.0.0.0"


def set_mocked_oracledb_provider(
    session: OracledbSession = None,
    identity: OracledbIdentityInfo = None,
    audit_config: dict = None,
):
    if session is None:
        session = OracledbSession(
            user=ORACLEDB_USER,
            dsn=ORACLEDB_DSN,
            connection=MagicMock(),
        )
    if identity is None:
        identity = OracledbIdentityInfo(
            user=ORACLEDB_USER,
            dsn=ORACLEDB_DSN,
            database_name=ORACLEDB_DATABASE_NAME,
            version=ORACLEDB_VERSION,
        )

    provider = MagicMock()
    provider.type = "oracledb"
    provider.auth_method = "User / Password"
    provider.session = session
    provider.identity = identity
    provider.audit_config = audit_config or {}
    provider.fixer_config = {}
    return provider


def set_mocked_connection(fetchall_results: list = None, fetchone_results: list = None):
    """Build a mocked python-oracledb connection whose cursor returns the
    given results, in order, across successive queries."""
    connection = MagicMock()
    cursor = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor
    if fetchall_results is not None:
        cursor.fetchall.side_effect = fetchall_results
    if fetchone_results is not None:
        cursor.fetchone.side_effect = fetchone_results
    return connection
