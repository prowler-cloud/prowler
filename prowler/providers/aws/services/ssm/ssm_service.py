import json
import time
from enum import Enum
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService

import pickle
import os
import atexit
from collections import deque
from sys import getsizeof
import tempfile
from memory_profiler import profile

class PaginatedDict:
    instance_counter = 0

    def __init__(self, page_size=100):
        self.page_size = page_size
        self.file_paths = []
        self.cache = {}
        self.key_to_page = {}
        self.length = 0  # Track the number of items
        self.instance_id = PaginatedDict.instance_counter
        PaginatedDict.instance_counter += 1
        self.temp_dir = tempfile.mkdtemp(prefix=f'paginated_dict_{self.instance_id}_', dir='/Users/snaow/repos/prowler')
        print(f"Temporary directory for instance {self.instance_id}: {self.temp_dir}")
        atexit.register(self.cleanup)
        
    def _save_page(self, page_data, page_num):
        file_path = os.path.join(self.temp_dir, f'page_{page_num}.pkl')
        with open(file_path, 'wb') as f:
            pickle.dump(page_data, f)
        if page_num >= len(self.file_paths):
            self.file_paths.append(file_path)
        else:
            self.file_paths[page_num] = file_path
    
    def _load_page(self, page_num):
        if page_num in self.cache:
            return self.cache[page_num]
        with open(self.file_paths[page_num], 'rb') as f:
            page_data = pickle.load(f)
        self.cache[page_num] = page_data
        return page_data

    def __setitem__(self, key, value):
        if key in self.key_to_page:
            page_num = self.key_to_page[key]
            page_data = self._load_page(page_num)
            page_data[key] = value
        else:
            page_num = self.length // self.page_size
            if page_num >= len(self.file_paths):
                self._save_page({}, page_num)
            page_data = self._load_page(page_num)
            page_data[key] = value
            self.key_to_page[key] = page_num
            self.length += 1
        self.cache[page_num] = page_data
        self._save_page(page_data, page_num)

    def __getitem__(self, key):
        if key not in self.key_to_page:
            raise KeyError(f"Key {key} not found")
        page_num = self.key_to_page[key]
        page_data = self._load_page(page_num)
        return page_data[key]

    def __delitem__(self, key):
        if key not in self.key_to_page:
            raise KeyError(f"Key {key} not found")
        page_num = self.key_to_page[key]
        page_data = self._load_page(page_num)
        del page_data[key]
        del self.key_to_page[key]
        self.cache[page_num] = page_data
        self._save_page(page_data, page_num)
        self.length -= 1

    def __len__(self):
        return self.length

    def __iter__(self):
        for page_num in range(len(self.file_paths)):
            page_data = self._load_page(page_num)
            for key in page_data:
                yield key

    def cleanup(self):
        for file_path in self.file_paths:
            if os.path.exists(file_path):
                os.remove(file_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def __del__(self):
        self.cleanup()

################## SSM
class SSM(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        paginated = 0
        if paginated == 1:
            self.documents = PaginatedDict()
            self.compliance_resources = PaginatedDict()
            self.managed_instances = PaginatedDict()
        else:
            self.documents = {}
            self.compliance_resources = {}
            self.managed_instances = {}

        self.__threading_call__(self.__list_documents__)
        self.__threading_call__(self.__get_document__)
        self.__threading_call__(self.__describe_document_permission__)
        self.__threading_call__(self.__list_resource_compliance_summaries__)
        self.__threading_call__(self.__describe_instance_information__)

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
                    document_arn = f"arn:{self.audited_partition}:ssm:{regional_client.region}:{self.audited_account}:document/{document_name}"
                    if not self.audit_resources or (
                        is_resource_filtered(document_arn, self.audit_resources)
                    ):
                        # We must use the Document ARN as the dict key to have unique keys
                        self.documents[document_arn] = Document(
                            arn=document_arn,
                            name=document_name,
                            region=regional_client.region,
                            tags=document.get("Tags"),
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __get_document__(self, regional_client):
        logger.info("SSM - Getting Document...")
        for document in self.documents.values():
            try:
                if document.region == regional_client.region:
                    document_info = regional_client.get_document(Name=document.name)
                    self.documents[document.arn].content = json.loads(
                        document_info["Content"]
                    )

            except ClientError as error:
                if error.response["Error"]["Code"] == "ValidationException":
                    logger.warning(
                        f"{regional_client.region} --"
                        f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                        f" {error}"
                    )
                    continue

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
                    self.documents[document.arn].account_owners = document_permissions[
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
                    resource_arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:instance/{resource_id}"
                    if not self.audit_resources or (
                        is_resource_filtered(resource_arn, self.audit_resources)
                    ):
                        resource_status = item["Status"]

                        self.compliance_resources[resource_id] = ComplianceResource(
                            id=resource_id,
                            arn=resource_arn,
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
                    resource_arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:instance/{resource_id}"
                    self.managed_instances[resource_id] = ManagedInstance(
                        arn=resource_arn,
                        id=resource_id,
                        region=regional_client.region,
                    )
                # boto3 does not properly handle throttling exceptions for
                # ssm:DescribeInstanceInformation when there are large numbers of instances
                # AWS support recommends manually reducing frequency of requests
                time.sleep(0.1)

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
    arn: str
    region: str
    status: ResourceStatus


class Document(BaseModel):
    arn: str
    name: str
    region: str
    content: dict = None
    account_owners: list[str] = None
    tags: Optional[list] = []


class ManagedInstance(BaseModel):
    arn: str
    id: str
    region: str
