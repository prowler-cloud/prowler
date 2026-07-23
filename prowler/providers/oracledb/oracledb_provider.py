import os
from os import environ

import oracledb
from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.oracledb.exceptions.exceptions import (
    OracledbConnectionError,
    OracledbEnvironmentVariableError,
    OracledbInvalidCredentialsError,
    OracledbInvalidProviderIdError,
    OracledbSetUpIdentityError,
    OracledbSetUpSessionError,
)
from prowler.providers.oracledb.lib.mutelist.mutelist import OracledbMutelist
from prowler.providers.oracledb.models import OracledbIdentityInfo, OracledbSession

DEFAULT_PORT = 1521


class OracledbProvider(Provider):
    """Oracle Database Provider class.

    Connects to a single Oracle Database (on-premises, in a VM or a cloud
    managed service) with python-oracledb in thin mode — no Oracle Client
    libraries are required — and runs security assessment checks inspired by
    the Oracle Database Security Assessment Tool (DBSAT) against the data
    dictionary (DBA_* and V$* views).

    Attributes:
        _type (str): The type of the provider.
        _auth_method (str): The authentication method used by the provider.
        _session (OracledbSession): The session object for the provider.
        _identity (OracledbIdentityInfo): The identity information for the provider.
        _audit_config (dict): The audit configuration for the provider.
        _fixer_config (dict): The fixer configuration for the provider.
        _mutelist (Mutelist): The mutelist for the provider.
        audit_metadata (Audit_Metadata): The audit metadata for the provider.
    """

    _type: str = "oracledb"
    sdk_only: bool = False
    _auth_method: str = "User / Password"
    _session: OracledbSession
    _identity: OracledbIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: Mutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        oracledb_user: str = "",
        oracledb_password: str = "",
        oracledb_dsn: str = "",
        oracledb_host: str = "",
        oracledb_port: int = None,
        oracledb_service_name: str = "",
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        """Oracle Database Provider constructor."""
        logger.info("Instantiating Oracle Database Provider...")

        OracledbProvider.validate_arguments(
            oracledb_user=oracledb_user,
            oracledb_password=oracledb_password,
            oracledb_dsn=oracledb_dsn,
            oracledb_host=oracledb_host,
            oracledb_service_name=oracledb_service_name,
        )
        self._session = OracledbProvider.setup_session(
            user=oracledb_user,
            password=oracledb_password,
            dsn=oracledb_dsn,
            host=oracledb_host,
            port=oracledb_port,
            service_name=oracledb_service_name,
        )
        self._identity = OracledbProvider.setup_identity(self._session)

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = OracledbMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = OracledbMutelist(mutelist_path=mutelist_path)

        Provider.set_global_provider(self)

    @property
    def auth_method(self):
        return self._auth_method

    @property
    def session(self):
        return self._session

    @property
    def identity(self):
        return self._identity

    @property
    def type(self):
        return self._type

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> OracledbMutelist:
        return self._mutelist

    @staticmethod
    def resolve_dsn(
        dsn: str = "", host: str = "", port: int = None, service_name: str = ""
    ) -> str:
        """Return the connect string, built from host/port/service when no DSN
        is given. An explicit DSN always wins so users can pass full Easy
        Connect strings (including protocol and wallet options) untouched."""
        dsn = dsn or environ.get("ORACLEDB_DSN", "")
        if dsn:
            return dsn.strip()
        host = host or environ.get("ORACLEDB_HOST", "")
        service_name = service_name or environ.get("ORACLEDB_SERVICE_NAME", "")
        if host and service_name:
            port = port or int(environ.get("ORACLEDB_PORT", DEFAULT_PORT))
            return f"{host.strip()}:{port}/{service_name.strip()}"
        return ""

    @staticmethod
    def validate_arguments(
        oracledb_user: str = "",
        oracledb_password: str = "",
        oracledb_dsn: str = "",
        oracledb_host: str = "",
        oracledb_service_name: str = "",
    ):
        """Validate that all required connection values are provided.

        Falls back to the matching `ORACLEDB_*` environment variables when a
        CLI argument is not supplied. Raises a single combined error if any
        required value is missing.
        """
        user = oracledb_user or environ.get("ORACLEDB_USER", "")
        password = oracledb_password or environ.get("ORACLEDB_PASSWORD", "")
        dsn = OracledbProvider.resolve_dsn(
            dsn=oracledb_dsn, host=oracledb_host, service_name=oracledb_service_name
        )

        missing = []
        if not user:
            missing.append("--oracledb-user / ORACLEDB_USER")
        if not password:
            missing.append("ORACLEDB_PASSWORD")
        if not dsn:
            missing.append(
                "--oracledb-dsn / ORACLEDB_DSN (or --oracledb-host and "
                "--oracledb-service-name)"
            )
        if missing:
            raise OracledbEnvironmentVariableError(
                file=os.path.basename(__file__),
                message=(
                    "Oracle Database provider requires the connection "
                    "credentials. Missing: " + ", ".join(missing)
                ),
            )

    @staticmethod
    def setup_session(
        user: str = "",
        password: str = "",
        dsn: str = "",
        host: str = "",
        port: int = None,
        service_name: str = "",
    ) -> OracledbSession:
        """Open a python-oracledb thin-mode connection from CLI args, falling
        back to environment variables.

        The password is read from `ORACLEDB_PASSWORD` when not supplied —
        secrets should be passed through environment variables, never CLI
        values.
        """
        try:
            user = user or environ.get("ORACLEDB_USER", "")
            password = password or environ.get("ORACLEDB_PASSWORD", "")
            resolved_dsn = OracledbProvider.resolve_dsn(
                dsn=dsn, host=host, port=port, service_name=service_name
            )

            connection = oracledb.connect(
                user=user, password=password, dsn=resolved_dsn
            )
            return OracledbSession(user=user, dsn=resolved_dsn, connection=connection)
        except oracledb.DatabaseError as error:
            # ORA-01017: invalid username/password — a credential problem, not
            # a connectivity one; keep the two remediation paths separate.
            if "ORA-01017" in str(error):
                raise OracledbInvalidCredentialsError(
                    file=os.path.basename(__file__),
                    original_exception=error,
                    message=f"Invalid Oracle Database credentials: {error}",
                )
            raise OracledbConnectionError(
                file=os.path.basename(__file__),
                original_exception=error,
                message=f"Could not connect to Oracle Database '{dsn}': {error}",
            )
        except (OracledbInvalidCredentialsError, OracledbConnectionError):
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise OracledbSetUpSessionError(original_exception=error)

    @staticmethod
    def setup_identity(session: OracledbSession) -> OracledbIdentityInfo:
        """Build the identity from the connected database.

        The database global name (GLOBAL_NAME view, readable by any user)
        identifies the audited database in outputs and the mutelist. The
        version is best-effort: PRODUCT_COMPONENT_VERSION may be restricted,
        in which case it is left empty rather than failing the scan.
        """
        try:
            with session.connection.cursor() as cursor:
                cursor.execute("SELECT global_name FROM global_name")
                database_name = cursor.fetchone()[0]

            version = ""
            try:
                with session.connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT version_full FROM product_component_version "
                        "WHERE product LIKE 'Oracle%'"
                    )
                    row = cursor.fetchone()
                    if row:
                        version = row[0]
            except Exception as error:
                logger.warning(
                    f"Could not read the Oracle Database version: "
                    f"{error.__class__.__name__}: {error}"
                )

            return OracledbIdentityInfo(
                user=session.user,
                dsn=session.dsn,
                database_name=database_name,
                version=version,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise OracledbSetUpIdentityError(original_exception=error)

    def print_credentials(self):
        report_lines = [
            f"Oracle Database: {Fore.YELLOW}{self.identity.database_name}{Style.RESET_ALL}",
            f"DSN: {Fore.YELLOW}{self.identity.dsn}{Style.RESET_ALL}",
            f"User: {Fore.YELLOW}{self.identity.user}{Style.RESET_ALL}",
        ]
        if self.identity.version:
            report_lines.append(
                f"Version: {Fore.YELLOW}{self.identity.version}{Style.RESET_ALL}"
            )
        report_title = f"{Style.BRIGHT}Using the Oracle Database credentials below:{Style.RESET_ALL}"
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        oracledb_user: str = "",
        oracledb_password: str = "",
        oracledb_dsn: str = "",
        oracledb_host: str = "",
        oracledb_port: int = None,
        oracledb_service_name: str = "",
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """Test the connection to an Oracle Database with the provided credentials.

        Args:
            provider_id: The provider ID (Oracle Database global name). When
                supplied, the connected database global name must match it —
                guards against the stored provider UID drifting from the
                database the credentials actually connect to. Compared
                case-insensitively; GLOBAL_NAME is stored uppercase.
        """
        try:
            OracledbProvider.validate_arguments(
                oracledb_user=oracledb_user,
                oracledb_password=oracledb_password,
                oracledb_dsn=oracledb_dsn,
                oracledb_host=oracledb_host,
                oracledb_service_name=oracledb_service_name,
            )
            session = OracledbProvider.setup_session(
                user=oracledb_user,
                password=oracledb_password,
                dsn=oracledb_dsn,
                host=oracledb_host,
                port=oracledb_port,
                service_name=oracledb_service_name,
            )
            try:
                identity = OracledbProvider.setup_identity(session)

                if (
                    provider_id
                    and provider_id.strip().upper() != identity.database_name.upper()
                ):
                    raise OracledbInvalidProviderIdError(
                        file=os.path.basename(__file__),
                        message=(
                            f"The provider ID '{provider_id}' does not match "
                            f"the connected Oracle Database global name "
                            f"'{identity.database_name}'."
                        ),
                    )
            finally:
                try:
                    session.connection.close()
                except Exception:
                    pass

            return Connection(is_connected=True)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)
