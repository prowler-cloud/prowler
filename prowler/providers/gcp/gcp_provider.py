import os
import pathlib
import sys

from google import auth
from googleapiclient import discovery
from googleapiclient.discovery import Resource

from prowler.config.config import gcp_zones_json_file
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file, parse_json_file
from prowler.providers.gcp.lib.audit_info.models import GCP_Audit_Info


class GCP_Provider:
    def __init__(
        self,
        user_account_auth: str,
        service_account_auth: str,
    ):
        logger.info("Instantiating GCP Provider ...")
        self.credentials, self.project_id = self.__set_credentials__(
            user_account_auth, service_account_auth
        )

    def __set_credentials__(self, user_account_auth, service_account_auth):
        if service_account_auth:
            self.__set_gcp_creds_env_var__(service_account_auth)
        elif user_account_auth:
            logger.info("GCP provider: Setting Google Account Credentials...")
        else:
            logger.critical(
                "Failed to authenticate to GCP - no supported authentication method"
            )
            sys.exit(1)

        return auth.default()

    def __set_gcp_creds_env_var__(self, service_account_auth):
        logger.info(
            "GCP provider: Setting GOOGLE_APPLICATION_CREDENTIALS environment variable..."
        )
        client_secrets_path = os.path.abspath(service_account_auth)
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = client_secrets_path

    def get_credentials(self):
        return self.credentials, self.project_id


def generate_client(
    service: str,
    api_version: str,
    audit_info: GCP_Audit_Info,
) -> Resource:
    try:
        return discovery.build(service, api_version, credentials=audit_info.credentials)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def get_gcp_available_zones():
    try:
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        with open_file(f"{actual_directory}/{gcp_zones_json_file}") as f:
            data = parse_json_file(f)

        return data["zones"]
    except Exception as error:
        logger.error(f"{error.__class__.__name__}: {error}")
        return []
