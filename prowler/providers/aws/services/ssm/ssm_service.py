import json
import threading
from enum import Enum

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## SSM
class SSM:
    def __init__(self, audit_info):
        self.service = "ssm"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.documents = {}
        self.compliance_resources = {}
        self.managed_instances = {}
        self.__threading_call__(self.__list_documents__)
        self.__threading_call__(self.__get_document__)
        self.__threading_call__(self.__describe_document_permission__)
        self.__threading_call__(self.__list_resource_compliance_summaries__)
        self.__threading_call__(self.__describe_instance_information__)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __list_documents__(self, regional_client):
        logger.info("SSM - Listing Documents...")
        try:
            # To retrieve only the documents owned by the account
            list_documents_parameters = {
                "Filters": [
                    {
                        "Key": "Owner",
                        "Values": [
                            "Self",
                        ],
                    },
                ],
            }
            list_documents_paginator = regional_client.get_paginator("list_documents")
            for page in list_documents_paginator.paginate(**list_documents_parameters):
                for document in page["DocumentIdentifiers"]:
                    document_name = document["Name"]

                    self.documents[document_name] = Document(
                        name=document_name,
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __get_document__(self, regional_client):
        logger.info("SSM - Getting Document...")
        try:
            for document in self.documents.values():
                if document.region == regional_client.region:
                    document_info = regional_client.get_document(Name=document.name)
                    self.documents[document.name].content = json.loads(
                        document_info["Content"]
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __describe_document_permission__(self, regional_client):
        logger.info("SSM - Describing Document Permission...")
        try:
            for document in self.documents.values():
                if document.region == regional_client.region:
                    document_permissions = regional_client.describe_document_permission(
                        Name=document.name, PermissionType="Share"
                    )
                    self.documents[document.name].account_owners = document_permissions[
                        "AccountIds"
                    ]

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __list_resource_compliance_summaries__(self, regional_client):
        logger.info("SSM - List Resources Compliance Summaries...")
        try:
            list_resource_compliance_summaries_paginator = (
                regional_client.get_paginator("list_resource_compliance_summaries")
            )
            for page in list_resource_compliance_summaries_paginator.paginate():
                for item in page["ResourceComplianceSummaryItems"]:
                    resource_id = item["ResourceId"]
                    resource_status = item["Status"]

                    self.compliance_resources[resource_id] = ComplianceResource(
                        id=resource_id,
                        status=resource_status,
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __describe_instance_information__(self, regional_client):
        logger.info("SSM - Describing Instance Information...")
        try:
            describe_instance_information_paginator = regional_client.get_paginator(
                "describe_instance_information"
            )
            for page in describe_instance_information_paginator.paginate():
                for item in page["InstanceInformationList"]:
                    resource_id = item["InstanceId"]

                    self.managed_instances[resource_id] = ManagedInstance(
                        id=resource_id,
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )


class ResourceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"


class ComplianceResource(BaseModel):
    id: str
    region: str
    status: ResourceStatus


class Document(BaseModel):
    name: str
    region: str
    content: dict = None
    account_owners: list[str] = None


class ManagedInstance(BaseModel):
    id: str
    region: str
