from prowler.lib.logger import logger
from prowler.providers.oracledb.lib.service.service import OracledbService
from prowler.providers.oracledb.oracledb_provider import OracledbProvider

# SYS-owned PL/SQL packages that DBSAT flags when they are executable by
# PUBLIC, grouped by the DBSAT finding they belong to.
NETWORK_PACKAGES = frozenset(
    {"UTL_HTTP", "UTL_TCP", "UTL_SMTP", "UTL_MAIL", "UTL_INADDR", "DBMS_LDAP"}
)  # PRIV.NETPACKAGEPUBLIC
FILE_PACKAGES = frozenset(
    {"UTL_FILE", "DBMS_LOB", "DBMS_ADVISOR"}
)  # PRIV.FILESYSTEMPACKAGEPUBLIC
ENCRYPTION_PACKAGES = frozenset(
    {"DBMS_CRYPTO", "DBMS_OBFUSCATION_TOOLKIT", "DBMS_RANDOM"}
)  # PRIV.ENCRYPTPACKAGEPUBLIC


class Privileges(OracledbService):
    """Oracle Database privileges service.

    Reads DBA_SYS_PRIVS and DBA_TAB_PRIVS to surface privileges granted to
    the PUBLIC role, mirroring the privileges and roles findings of the
    Oracle Database Security Assessment Tool (DBSAT).
    """

    def __init__(self, provider: OracledbProvider):
        super().__init__(__class__.__name__, provider)
        self.public_system_privileges = self._list_public_system_privileges()
        self.public_execute_packages = self._list_public_execute_packages()

    def _list_public_system_privileges(self) -> list[str]:
        """List system privileges granted to PUBLIC (DBSAT PRIV.SYSPUBLIC)."""
        logger.info("Privileges - Listing system privileges granted to PUBLIC...")
        privileges = []
        try:
            rows = self._execute_query(
                "SELECT privilege FROM dba_sys_privs WHERE grantee = 'PUBLIC'"
            )
            privileges = sorted(row[0] for row in rows)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return privileges

    def _list_public_execute_packages(self) -> list[str]:
        """List SYS-owned packages executable by PUBLIC.

        The checks intersect this list with the DBSAT package groups
        (network, file system, encryption) defined above.
        """
        logger.info("Privileges - Listing SYS packages executable by PUBLIC...")
        packages = []
        try:
            rows = self._execute_query(
                "SELECT table_name FROM dba_tab_privs "
                "WHERE grantee = 'PUBLIC' AND privilege = 'EXECUTE' "
                "AND owner = 'SYS'"
            )
            packages = sorted(row[0] for row in rows)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return packages
