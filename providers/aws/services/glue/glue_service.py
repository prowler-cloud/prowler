import threading
from typing import Optional

from pydantic import BaseModel

from lib.logger import logger
from providers.aws.aws_provider import generate_regional_clients


################## Glue
class Glue:
    def __init__(self, audit_info):
        self.service = "glue"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.connections = []
        self.__threading_call__(self.__get_connections__)
        self.tables = []
        self.__threading_call__(self.__search_tables__)
        self.catalog_encryption_settings = []
        self.__threading_call__(self.__get_data_catalog_encryption_settings__)

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

    def __get_connections__(self, regional_client):
        logger.info("Glue - Getting connections...")
        try:
            get_connections_paginator = regional_client.get_paginator("get_connections")
            for page in get_connections_paginator.paginate():
                for conn in page["ConnectionList"]:
                    self.connections.append(
                        Connection(
                            name=conn["Name"],
                            type=conn["ConnectionType"],
                            properties=conn["ConnectionProperties"],
                            region=regional_client.region,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )

    def __search_tables__(self, regional_client):
        logger.info("Glue - Search Tables...")
        try:
            get_connections_paginator = regional_client.get_paginator("search_tables")
            for page in get_connections_paginator.paginate():
                for table in page["TableList"]:
                    self.tables.append(
                        Table(
                            name=table["Name"],
                            database=table["DatabaseName"],
                            catalog=table["CatalogId"],
                            region=regional_client.region,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )

    def __get_data_catalog_encryption_settings__(self, regional_client):
        logger.info("Glue - Catalog Encryption Settings...")
        try:
            settings = regional_client.get_data_catalog_encryption_settings()[
                "DataCatalogEncryptionSettings"
            ]
            self.catalog_encryption_settings.append(
                CatalogEncryptionSetting(
                    mode=settings["EncryptionAtRest"]["CatalogEncryptionMode"],
                    kms_id=settings["EncryptionAtRest"].get("SseAwsKmsKeyId"),
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )


class Connection(BaseModel):
    name: str
    type: str
    properties: dict
    region: str


class Table(BaseModel):
    name: str
    database: str
    catalog: dict
    region: str


class CatalogEncryptionSetting(BaseModel):
    mode: str
    kms_id: Optional[str]
    region: str
