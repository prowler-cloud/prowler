import sys
import json
import os
from typing import Any, Optional, Tuple

import ionoscloud
from ionoscloud import ApiClient, Configuration
from ionoscloud.rest import ApiException
import ionoscloud_dataplatform

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.providers.ionos.lib.mutelist.mutelist import IonosMutelist

from prowler.providers.common.provider import Provider

class IonosProvider(Provider):
    _type: str = "ionos"
    _session: Optional[ApiClient] = None
    _identity: Optional[str] = None
    _audit_config: dict = {}
    _output_options: Optional[Any] = None
    _mutelist: IonosMutelist
    audit_metadata: Optional[Any] = None

    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        config_path: Optional[str] = None,
        mutelist_path: Optional[str] = None,
        mutelist_content: dic = None,
    ):
        """
        Inicializa la clase IonosProvider y configura la sesión.
        Si no se proporcionan credenciales se intentará cargarlas desde variables de entorno o la configuración de ionosctl.
        """
        logger.info("Initializing IONOS Provider...")
        # Se asigna la identidad (usuario)
        self._identity = username
        self._audit_config = load_and_validate_config_file("ionos", config_path)
        self._mutelist = Mutelist(mutelist_path) if mutelist_path else None

        # Si no se pasan usuario o contraseña, se cargan desde las variables de entorno.
        if not username or not password:
            username, password, token = self.load_env_credentials()
        else:
            # Si se proporcionan explícitamente, se puede intentar obtener el token del entorno o asignarlo a None
            token = os.getenv("IONOS_TOKEN")

        self.setup_session(username, password, token)

        # Mutelist
        if mutelist_content:
            self._mutelist = IonosMutelist(
                mutelist_content=mutelist_content,
                session=self._session.current_session,
                #aws_account_id=self._identity.account,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = IonosMutelist(
                mutelist_path=mutelist_path,
                session=self._session.current_session,
                #aws_account_id=self._identity.account,
            )

        # Se asigna la instancia global usando el método de la clase base.
        Provider.set_global_provider(self)

    @staticmethod
    def load_env_credentials() -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Lee las credenciales de IONOS desde las variables de entorno.
        Retorna una tupla con (username, password, token)
        """
        print('hola que tal')
        username = os.getenv("IONOS_USERNAME")
        password = os.getenv("IONOS_PASSWORD")
        token = os.getenv("IONOS_TOKEN")
        if username and password and token:
            logger.info("Loaded IONOS credentials from environment variables.")
        else:
            logger.warning("No se encontraron todas las credenciales en las variables de entorno.")
        return username, password, token

    @staticmethod
    def load_ionosctl_credentials() -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Lee las credenciales de IONOS desde el archivo de configuración de ionosctl.
        Nota: Se amplía para incluir token si fuese necesario.
        """
        config_path = os.path.expanduser("~/.config/ionosctl/config.json")
        try:
            with open(config_path, "r") as config_file:
                config = json.load(config_file)
                logger.info("Loaded IONOS credentials from ionosctl config file.")
                # Se asume que el token puede estar en el config, si no, se retorna None.
                return config.get("username"), config.get("password"), config.get("token")
        except (FileNotFoundError, json.JSONDecodeError) as error:
            logger.warning(f"Failed to load IONOS credentials from ionosctl: {error}")
            return None, None, None

    @property
    def type(self) -> str:
        return self._type

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def session(self) -> ApiClient:
        return self._session

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def mutelist(self) -> IonosMutelist:
        """
        mutelist method returns the provider's mutelist
        """
        return self._mutelist

    def setup_session(
        self, 
        username: str, 
        password: str, 
        token: Optional[str]
    ):
        """
        Configura la sesión para interactuar con la API de IONOS Cloud.
        """
        try:
            # Se utiliza la librería ionoscloud_dataplatform para configurar la sesión.
            config = ionoscloud_dataplatform.Configuration(username=username, password=password, token=token)
            self._session = ionoscloud_dataplatform.ApiClient(configuration=config)
            logger.info("Successfully initialized IONOS Cloud API session.")
        except Exception as error:
            logger.critical(f"Failed to initialize IONOS session: {error}")
            sys.exit(1)

    def print_credentials(self) -> None:
        """
        Muestra la identidad del proveedor en el CLI.
        """
        logger.info(f"IONOS Provider Identity: {self._identity}")

    def test_connection(self) -> bool:
        """
        Prueba la conexión con la API de IONOS.
        """
        try:
            datacenter_api = ionoscloud.DataCenterApi(self._session)
            datacenters = datacenter_api.datacenters_get()
            logger.info("Successfully connected to IONOS Cloud API.")
            return True
        except ApiException as error:
            logger.error(f"Failed to connect to IONOS Cloud API: {error}")
            return False

    def get_datacenters(self) -> list:
        """
        Recupera la lista de datacenters de la cuenta IONOS.
        """
        try:
            datacenter_api = ionoscloud.DataCenterApi(self._session)
            datacenters = datacenter_api.datacenters_get().items
            logger.info("Successfully retrieved datacenters from IONOS Cloud API.")
            return datacenters
        except ApiException as error:
            logger.error(f"Failed to retrieve datacenters from IONOS Cloud API: {error}")
            return []
