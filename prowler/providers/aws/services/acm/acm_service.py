import threading
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## ACM
class ACM:
    def __init__(self, audit_info):
        self.service = "acm"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.certificates = []
        self.__threading_call__(self.__list_certificates__)
        self.__describe_certificates__()
        self.__list_tags_for_certificate__()

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

    def __list_certificates__(self, regional_client):
        logger.info("ACM - Listing Certificates...")
        try:
            list_certificates_paginator = regional_client.get_paginator(
                "list_certificates"
            )
            for page in list_certificates_paginator.paginate():
                for certificate in page["CertificateSummaryList"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            certificate["CertificateArn"], self.audit_resources
                        )
                    ):
                        if "NotAfter" in certificate:
                            # We need to get the TZ info to be able to do the math
                            certificate_expiration_time = (
                                certificate["NotAfter"]
                                - datetime.now(
                                    certificate["NotAfter"].tzinfo
                                    if hasattr(certificate["NotAfter"], "tzinfo")
                                    else None
                                )
                            ).days
                        else:
                            certificate_expiration_time = 0
                        self.certificates.append(
                            Certificate(
                                arn=certificate["CertificateArn"],
                                name=certificate["DomainName"],
                                type=certificate["Type"],
                                expiration_days=certificate_expiration_time,
                                transparency_logging=False,
                                region=regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_certificates__(self):
        logger.info("ACM - Describing Certificates...")
        try:
            for certificate in self.certificates:
                regional_client = self.regional_clients[certificate.region]
                response = regional_client.describe_certificate(
                    CertificateArn=certificate.arn
                )["Certificate"]
                if (
                    response["Options"]["CertificateTransparencyLoggingPreference"]
                    == "ENABLED"
                ):
                    certificate.transparency_logging = True
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags_for_certificate__(self):
        logger.info("ACM - List Tags...")
        try:
            for certificate in self.certificates:
                regional_client = self.regional_clients[certificate.region]
                response = regional_client.list_tags_for_certificate(
                    CertificateArn=certificate.arn
                )["Tags"]
                certificate.tags = [response]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Certificate(BaseModel):
    arn: str
    name: str
    type: str
    tags: list = []
    expiration_days: int
    transparency_logging: Optional[bool]
    region: str
