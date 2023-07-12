import json
import threading
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## Glacier
class Glacier:
    def __init__(self, audit_info):
        self.service = "glacier"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.vaults = {}
        self.__threading_call__(self.__list_vaults__)
        self.__threading_call__(self.__get_vault_access_policy__)
        self.__list_tags_for_vault__()

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

    def __list_vaults__(self, regional_client):
        logger.info("Glacier - Listing Vaults...")
        try:
            list_vaults_paginator = regional_client.get_paginator("list_vaults")
            for page in list_vaults_paginator.paginate():
                for vault in page["VaultList"]:
                    if not self.audit_resources or (
                        is_resource_filtered(vault["VaultARN"], self.audit_resources)
                    ):
                        vault_name = vault["VaultName"]
                        vault_arn = vault["VaultARN"]
                        # We must use the Vault ARN as the dict key to have unique keys
                        self.vaults[vault_arn] = Vault(
                            name=vault_name,
                            arn=vault_arn,
                            region=regional_client.region,
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __get_vault_access_policy__(self, regional_client):
        logger.info("Glacier - Getting Vault Access Policy...")
        try:
            for vault in self.vaults.values():
                if vault.region == regional_client.region:
                    try:
                        vault_access_policy = regional_client.get_vault_access_policy(
                            vaultName=vault.name
                        )
                        self.vaults[vault.arn].access_policy = json.loads(
                            vault_access_policy["policy"]["Policy"]
                        )
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "ResourceNotFoundException":
                            self.vaults[vault.arn].access_policy = {}
        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def __list_tags_for_vault__(self):
        logger.info("Glacier - List Tags...")
        try:
            for vault in self.vaults.values():
                regional_client = self.regional_clients[vault.region]
                response = regional_client.list_tags_for_vault(vaultName=vault.name)[
                    "Tags"
                ]
                vault.tags = [response]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Vault(BaseModel):
    name: str
    arn: str
    region: str
    access_policy: dict = {}
    tags: Optional[list] = []
