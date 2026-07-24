from prowler.lib.logger import logger
from prowler.providers.oracledb.lib.service.service import OracledbService
from prowler.providers.oracledb.oracledb_provider import OracledbProvider

# Security-relevant initialization parameters evaluated by the configuration
# checks (DBSAT CONF.* findings).
SECURITY_PARAMETERS = (
    "o7_dictionary_accessibility",
    "sql92_security",
    "remote_os_authent",
    "remote_os_roles",
    "remote_login_passwordfile",
    "sec_return_server_release_banner",
)


class Configuration(OracledbService):
    """Oracle Database configuration service.

    Reads security-relevant initialization parameters from V$PARAMETER,
    mirroring the database configuration findings of the Oracle Database
    Security Assessment Tool (DBSAT).
    """

    def __init__(self, provider: OracledbProvider):
        super().__init__(__class__.__name__, provider)
        self.parameters = self._get_parameters()

    def _get_parameters(self) -> dict:
        """Read the security-relevant initialization parameters.

        Returns:
            dict: {parameter_name: value}. Parameters removed in newer
            releases (e.g. REMOTE_OS_AUTHENT was desupported in 12c) are
            simply absent; checks treat absence as the secure default.
        """
        logger.info("Configuration - Reading initialization parameters...")
        parameters = {}
        try:
            in_list = ", ".join(f"'{parameter}'" for parameter in SECURITY_PARAMETERS)
            rows = self._execute_query(
                f"SELECT name, value FROM v$parameter WHERE name IN ({in_list})"
            )
            parameters = {name: value for name, value in rows}
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return parameters
