from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from prowler.providers.oracledb.oracledb_provider import OracledbProvider


class OracledbService:
    """Base class for Oracle Database service implementations.

    Every service shares the single authenticated python-oracledb connection
    opened by the provider — Oracle sessions are expensive and the data
    dictionary queries the checks need are all read-only.
    """

    def __init__(self, service: str, provider: "OracledbProvider"):
        self.provider = provider
        self.service = service
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.connection = provider.session.connection
        self.database_name = provider.identity.database_name

    def _execute_query(self, query: str, parameters: dict = None) -> list[tuple]:
        """Run a read-only data dictionary query and return every row.

        Args:
            query: The SQL statement to execute.
            parameters: Optional bind variables for the statement.

        Returns:
            list[tuple]: All rows returned by the query.
        """
        with self.connection.cursor() as cursor:
            cursor.execute(query, parameters or {})
            return cursor.fetchall()
