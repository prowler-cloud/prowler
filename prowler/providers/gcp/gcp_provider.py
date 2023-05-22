import os
import sys

from google import auth
from googleapiclient import discovery
from googleapiclient.discovery import Resource

from prowler.lib.logger import logger
from prowler.providers.gcp.lib.audit_info.models import GCP_Audit_Info


class GCP_Provider:
    def __init__(
        self,
        credentials_file: str,
    ):
        logger.info("Instantiating GCP Provider ...")
        self.credentials, self.default_project_id = self.__set_credentials__(
            credentials_file
        )
        if not self.default_project_id:
            logger.critical("No Project ID associated to Google Credentials.")
            sys.exit(1)

        self.project_ids = self.get_project_ids()
        if not self.project_ids:
            logger.critical("No Project IDs can be accessed via Google Credentials.")
            sys.exit(1)

    def __set_credentials__(self, credentials_file):
        try:
            if credentials_file:
                self.__set_gcp_creds_env_var__(credentials_file)

            return auth.default()
        except Exception as error:
            logger.critical(f"{error.__class__.__name__} -- {error}")
            sys.exit(1)

    def __set_gcp_creds_env_var__(self, credentials_file):
        logger.info(
            "GCP provider: Setting GOOGLE_APPLICATION_CREDENTIALS environment variable..."
        )
        client_secrets_path = os.path.abspath(credentials_file)
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = client_secrets_path

    def get_credentials(self):
        return self.credentials, self.default_project_id, self.project_ids

    def get_project_ids(self):
        try:
            project_ids = []

            service = discovery.build(
                "cloudresourcemanager", "v1", credentials=self.credentials
            )

            request = service.projects().list()

            while request is not None:
                response = request.execute()

                for project in response.get("projects", []):
                    project_ids.append(project["projectId"])

                request = service.projects().list_next(
                    previous_request=request, previous_response=response
                )

            return project_ids
        except Exception as error:
            logger.critical(f"{error.__class__.__name__} -- {error}")
            sys.exit(1)


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
