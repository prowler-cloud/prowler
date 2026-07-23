from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oracledb.lib.service.service import OracledbService
from prowler.providers.oracledb.oracledb_provider import OracledbProvider

# Oracle-managed tablespaces excluded from the TDE tablespace check: they hold
# the data dictionary or transient data and are reported separately by DBSAT.
SYSTEM_TABLESPACES = frozenset({"SYSTEM", "SYSAUX"})


class Encryption(OracledbService):
    """Oracle Database encryption service.

    Reads V$ENCRYPTION_WALLET and DBA_TABLESPACES to evaluate Transparent
    Data Encryption (TDE) posture, mirroring the encryption findings of the
    Oracle Database Security Assessment Tool (DBSAT).
    """

    def __init__(self, provider: OracledbProvider):
        super().__init__(__class__.__name__, provider)
        self.wallets = self._list_wallets()
        self.tablespaces = self._list_tablespaces()

    def _list_wallets(self) -> list["Wallet"]:
        """List the TDE keystore(s) configured for the database."""
        logger.info("Encryption - Listing TDE keystores...")
        wallets = []
        try:
            rows = self._execute_query(
                "SELECT wrl_type, wrl_parameter, status, wallet_type "
                "FROM v$encryption_wallet"
            )
            for wrl_type, wrl_parameter, status, wallet_type in rows:
                wallets.append(
                    Wallet(
                        wrl_type=wrl_type or "",
                        wrl_parameter=wrl_parameter or "",
                        status=status or "",
                        wallet_type=wallet_type or "",
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return wallets

    def _list_tablespaces(self) -> list["Tablespace"]:
        """List permanent tablespaces and their encryption status."""
        logger.info("Encryption - Listing tablespaces...")
        tablespaces = []
        try:
            rows = self._execute_query(
                "SELECT tablespace_name, encrypted, contents FROM dba_tablespaces"
            )
            for name, encrypted, contents in rows:
                tablespaces.append(
                    Tablespace(
                        name=name,
                        encrypted=encrypted == "YES",
                        contents=contents or "",
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        logger.info(f"Found {len(tablespaces)} tablespaces")
        return tablespaces


class Wallet(BaseModel):
    """Oracle Database TDE keystore model (V$ENCRYPTION_WALLET row)."""

    wrl_type: str = ""
    wrl_parameter: str = ""
    status: str = ""
    wallet_type: str = ""


class Tablespace(BaseModel):
    """Oracle Database tablespace model."""

    name: str
    encrypted: bool = False
    contents: str = ""

    @property
    def is_user_permanent(self) -> bool:
        """True for permanent, non-Oracle-managed tablespaces — the ones the
        TDE check evaluates. Temporary and undo tablespaces hold transient
        data and follow the encryption of the data they stage."""
        return self.contents == "PERMANENT" and self.name not in SYSTEM_TABLESPACES
