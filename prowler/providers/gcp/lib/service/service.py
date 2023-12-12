import threading

import google_auth_httplib2
import httplib2
from colorama import Fore, Style
from google.oauth2.credentials import Credentials
from googleapiclient import discovery
from googleapiclient.discovery import Resource

from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider_new import GcpProvider


class GCPService:
    def __init__(
        self,
        service: str,
        provider: GcpProvider,
        region="global",
        api_version="v1",
    ):
        # We receive the service using __class__.__name__ or the service name in lowercase
        # e.g.: APIKeys --> we need a lowercase string, so service.lower()
        self.service = service.lower() if not service.islower() else service
        self.credentials = provider.session
        self.api_version = api_version
        self.default_project_id = provider.default_project_id
        self.region = region
        self.client = self.__generate_client__(service, api_version, self.credentials)
        # Only project ids that have their API enabled will be scanned
        self.project_ids = self.__is_api_active__(provider.project_ids)

    def __get_client__(self):
        return self.client

    def __threading_call__(self, call, iterator):
        threads = []
        for value in iterator:
            threads.append(threading.Thread(target=call, args=(value,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __get_AuthorizedHttp_client__(self):
        return google_auth_httplib2.AuthorizedHttp(
            self.credentials, http=httplib2.Http()
        )

    def __is_api_active__(self, audited_project_ids):
        project_ids = []
        for project_id in audited_project_ids:
            try:
                client = discovery.build("serviceusage", "v1")
                request = client.services().get(
                    name=f"projects/{project_id}/services/{self.service}.googleapis.com"
                )
                response = request.execute()
                if response.get("state") != "DISABLED":
                    project_ids.append(project_id)
                else:
                    print(
                        f"\n{Fore.YELLOW}{self.service} API {Style.RESET_ALL}has not been used in project {project_id} before or it is disabled.\nEnable it by visiting https://console.developers.google.com/apis/api/dataproc.googleapis.com/overview?project={project_id} then retry."
                    )
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return project_ids

    def __generate_client__(
        self,
        service: str,
        api_version: str,
        credentials: Credentials,
    ) -> Resource:
        try:
            return discovery.build(service, api_version, credentials=credentials)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
