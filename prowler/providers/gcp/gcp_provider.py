import os
import sys

from google import auth
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from prowler.lib.logger import logger


class GCP_Provider:
    def __init__(
        self,
        credentials_file: str,
        input_project_ids: list,
    ):
        logger.info("Instantiating GCP Provider ...")
        self.credentials = self.__set_credentials__(credentials_file)

        self.project_ids = []
        accessible_projects = self.get_project_ids()
        if not accessible_projects:
            logger.critical("No Project IDs can be accessed via Google Credentials.")
            sys.exit(1)

        if input_project_ids:
            for input_project in input_project_ids:
                if input_project in accessible_projects:
                    self.project_ids.append(input_project)
                else:
                    logger.critical(
                        f"Project {input_project} cannot be accessed via Google Credentials."
                    )
                    sys.exit(1)
        else:
            # If not projects were input, all accessible projects are scanned by default
            self.project_ids = accessible_projects

    def __set_credentials__(self, credentials_file):
        try:
            if credentials_file:
                self.__set_gcp_creds_env_var__(credentials_file)

            credentials, _ = auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
            return credentials
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    def __set_gcp_creds_env_var__(self, credentials_file):
        logger.info(
            "GCP provider: Setting GOOGLE_APPLICATION_CREDENTIALS environment variable..."
        )
        client_secrets_path = os.path.abspath(credentials_file)
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = client_secrets_path

    def get_credentials(self):
        return self.credentials, self.project_ids

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

        except HttpError as http_error:
            if "Cloud Resource Manager API has not been used" in str(http_error):
                logger.critical(
                    "Cloud Resource Manager API has not been used before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/cloudresourcemanager.googleapis.com/ then retry."
                )
                sys.exit(1)
            else:
                logger.error(
                    f"{http_error.__class__.__name__}[{http_error.__traceback__.tb_lineno}]: {http_error}"
                )
        except Exception as error:
            if error.__class__.__name__ == "RefreshError":
                logger.critical(
                    "Google Cloud SDK has not been authenticated or the credentials have expired. Authenticate by running 'gcloud auth application-default login' then retry."
                )
            else:
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            sys.exit(1)
        finally:
            return project_ids
