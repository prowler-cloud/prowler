import os
import sys

from colorama import Fore, Style
from google import auth
from google.oauth2.credentials import Credentials
from googleapiclient import discovery

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.gcp.models import GCPIdentityInfo, GCPOutputOptions


class GcpProvider(Provider):
    _type: str = "gcp"
    _session: Credentials
    _project_ids: list
    _identity: GCPIdentityInfo
    _audit_config: dict
    _output_options: GCPOutputOptions
    # TODO: enforce the mutelist for the Provider class
    # _mutelist: dict = {}
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(self, arguments):
        logger.info("Instantiating GCP Provider ...")
        input_project_ids = arguments.project_ids
        credentials_file = arguments.credentials_file

        self._session, default_project_id = self.setup_session(credentials_file)

        self._project_ids = []
        accessible_projects = self.get_project_ids()
        if not accessible_projects:
            logger.critical("No Project IDs can be accessed via Google Credentials.")
            sys.exit(1)

        if input_project_ids:
            for input_project in input_project_ids:
                if input_project in accessible_projects:
                    self._project_ids.append(input_project)
                else:
                    logger.critical(
                        f"Project {input_project} cannot be accessed via Google Credentials."
                    )
                    sys.exit(1)
        else:
            # If not projects were input, all accessible projects are scanned by default
            self._project_ids = accessible_projects

        self._identity = GCPIdentityInfo(
            profile=getattr(self.session, "_service_account_email", "default"),
            default_project_id=default_project_id,
        )

        # TODO: move this to the providers, pending for AWS, GCP, AZURE and K8s
        # Audit Config
        self._audit_config = load_and_validate_config_file(
            self._type, arguments.config_file
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
    def project_ids(self):
        return self._project_ids

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def output_options(self):
        return self._output_options

    @output_options.setter
    def output_options(self, options: tuple):
        arguments, bulk_checks_metadata = options
        self._output_options = GCPOutputOptions(
            arguments, bulk_checks_metadata, self._identity
        )

    # TODO: pending to implement
    # @property
    # def mutelist(self):
    #     return self._mutelist

    # @mutelist.setter
    # def mutelist(self, mutelist_path):
    #     if mutelist_path:
    #         mutelist = parse_mutelist_file(
    #             self._session.current_session, self._identity.account, mutelist_path
    #         )
    #     else:
    #         mutelist = {}
    #     self._mutelist = mutelist

    def setup_session(self, credentials_file):
        try:
            if credentials_file:
                self.__set_gcp_creds_env_var__(credentials_file)

            return auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"]
            )
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
        # Beautify audited profile, set "default" if there is no profile set

        report = f"""
This report is being generated using credentials below:

GCP Account: {Fore.YELLOW}[{self.identity.profile}]{Style.RESET_ALL}  GCP Project IDs: {Fore.YELLOW}[{", ".join(self.project_ids)}]{Style.RESET_ALL}
"""
        print(report)

    def get_project_ids(self):
        try:
            project_ids = []

            service = discovery.build(
                "cloudresourcemanager", "v1", credentials=self.session
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
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            print(
                f"\n{Fore.YELLOW}Cloud Resource Manager API {Style.RESET_ALL}has not been used before or it is disabled.\nEnable it by visiting https://console.developers.google.com/apis/api/cloudresourcemanager.googleapis.com/ then retry."
            )
            return []
