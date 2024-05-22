import os
import re
import sys

from colorama import Fore, Style
from google import auth
from google.oauth2.credentials import Credentials
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.gcp.models import (
    GCPIdentityInfo,
    GCPOrganization,
    GCPOutputOptions,
    GCPProject,
)


class GcpProvider(Provider):
    _type: str = "gcp"
    _session: Credentials
    _project_ids: list
    _excluded_project_ids: list
    _identity: GCPIdentityInfo
    _audit_config: dict
    _output_options: GCPOutputOptions
    _mutelist: dict
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(self, arguments):
        logger.info("Instantiating GCP Provider ...")
        input_project_ids = arguments.project_id
        excluded_project_ids = arguments.excluded_project_id
        credentials_file = arguments.credentials_file
        list_project_ids = arguments.list_project_id

        self._session = self.setup_session(credentials_file)

        self._project_ids = []
        self._projects = {}
        self._excluded_project_ids = []
        accessible_projects = self.get_projects()
        if not accessible_projects:
            logger.critical("No Project IDs can be accessed via Google Credentials.")
            sys.exit(1)

        if input_project_ids:
            for input_project in input_project_ids:
                for accessible_project in accessible_projects:
                    if self.is_project_matching(input_project, accessible_project):
                        self._projects[accessible_project] = accessible_projects[
                            accessible_project
                        ]
                        self._project_ids.append(
                            accessible_projects[accessible_project].id
                        )
        else:
            # If not projects were input, all accessible projects are scanned by default
            for project_id, project in accessible_projects.items():
                self._projects[project_id] = project
                self._project_ids.append(project_id)

        # Remove excluded projects if any input
        if excluded_project_ids:
            for excluded_project in excluded_project_ids:
                for project_id in self._project_ids:
                    if self.is_project_matching(excluded_project, project_id):
                        self._excluded_project_ids.append(project_id)
            for project_id in self._excluded_project_ids:
                self._projects.pop(project_id)
                self._project_ids.remove(project_id)

        if not self._projects:
            logger.critical(
                "No Input Project IDs can be accessed via Google Credentials."
            )
            sys.exit(1)

        if list_project_ids:
            print(
                f"{Fore.YELLOW}Available GCP Project IDs{Style.RESET_ALL}:\n{' '.join(self._project_ids)}\n"
            )
            sys.exit(0)

        # Update organizations info
        self.update_projects_with_organizations()

        self._identity = GCPIdentityInfo(
            profile=getattr(self.session, "_service_account_email", "default"),
        )

        # TODO: move this to the providers, pending for AWS, GCP, AZURE and K8s
        # Audit Config
        self._audit_config = load_and_validate_config_file(
            self._type, arguments.config_file
        )
        self._fixer_config = load_and_validate_config_file(
            self._type, arguments.fixer_config
        )

    @property
    def identity(self):
        return self._identity

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def projects(self):
        return self._projects

    @property
    def project_ids(self):
        return self._project_ids

    @property
    def excluded_project_ids(self):
        return self._excluded_project_ids

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def output_options(self):
        return self._output_options

    @output_options.setter
    def output_options(self, options: tuple):
        arguments, bulk_checks_metadata = options
        self._output_options = GCPOutputOptions(
            arguments, bulk_checks_metadata, self._identity
        )

    @property
    def get_output_mapping(self):
        return {
            # Account: identity.profile
            "auth_method": "identity.profile",
            "provider": "type",
            # TODO: comes from finding, finding.project_id
            # "account_uid": "",
            # TODO: get project name from GCP
            # "account_name": "organizations_metadata.account_details_name",
            # There is no concept as project email in GCP
            # "account_email": "organizations_metadata.account_details_email",
            # TODO: get project organization ID from GCP
            # "account_organization_uid": "organizations_metadata.account_details_arn",
            # TODO: get project organization from GCP
            # "account_organization": "",
            # TODO: get project tags organization from GCP
            # "account_tags": "organizations_metadata.account_details_tags",
            # "partition": "identity.partition",
        }

    def setup_session(self, credentials_file):
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

    def print_credentials(self):
        # TODO: Beautify audited profile, set "default" if there is no profile set
        # TODO: improve print_credentials with more data like name, number, organization
        report_lines = [
            f"GCP Account: {Fore.YELLOW}{self.identity.profile}{Style.RESET_ALL}",
            f"GCP Project IDs: {Fore.YELLOW}{', '.join(self.project_ids)}{Style.RESET_ALL}",
        ]
        if self.excluded_project_ids:
            report_lines.append(
                f"Excluded GCP Project IDs: {Fore.YELLOW}{', '.join(self.excluded_project_ids)}{Style.RESET_ALL}"
            )
        report_title = (
            f"{Style.BRIGHT}Using the GCP credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    def get_projects(self) -> dict[str, GCPProject]:
        try:
            projects = {}

            service = discovery.build(
                "cloudresourcemanager", "v1", credentials=self.session
            )

            request = service.projects().list()

            while request is not None:
                response = request.execute()

                for project in response.get("projects", []):
                    labels = []
                    for key, value in project.get("labels", {}).items():
                        labels.append(f"{key}:{value}")

                    project_id = project["projectId"]
                    gcp_project = GCPProject(
                        number=project["projectNumber"],
                        id=project_id,
                        name=project["name"],
                        lifecycle_state=project["lifecycleState"],
                        labels=labels,
                    )

                    if (
                        "parent" in project
                        and "type" in project["parent"]
                        and project["parent"]["type"] == "organization"
                    ):
                        organization_id = project["parent"]["id"]
                        gcp_project.organization = GCPOrganization(
                            id=organization_id, name=f"organizations/{organization_id}"
                        )

                    projects[project_id] = gcp_project
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
            return projects

    def update_projects_with_organizations(self):
        try:
            service = discovery.build(
                "cloudresourcemanager", "v1", credentials=self._session
            )
            # TODO: this call requires more permissions to get that data
            # resourcemanager.organizations.get --> add to the docs
            for project in self._projects.values():
                if project.organization:
                    request = service.organizations().get(
                        name=f"organizations/{project.organization.id}"
                    )

                    while request is not None:
                        response = request.execute()
                        project.organization.display_name = response.get("displayName")
                        request = service.projects().list_next(
                            previous_request=request, previous_response=response
                        )

        except HttpError as http_error:
            if http_error.status_code == 403 and "organizations" in http_error.uri:
                logger.error(
                    f"{http_error.__class__.__name__}[{http_error.__traceback__.tb_lineno}]: {http_error.error_details} to get Organizations display name."
                )
            else:
                logger.error(
                    f"{http_error.__class__.__name__}[{http_error.__traceback__.tb_lineno}]: {http_error}"
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def is_project_matching(self, input_project: str, project_to_match: str) -> bool:
        """
        Check if the input project matches the project to match
        Args:
            input_project: str
            project_to_match: str
        Returns:
            bool
        """
        return (
            "*" in input_project
            and re.search(
                "." + input_project if input_project.startswith("*") else input_project,
                project_to_match,
            )
        ) or input_project == project_to_match
