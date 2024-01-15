from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## ACM
class ACM(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.certificates = []
        self.__threading_call__(self.__list_certificates__)
        self.__threading_call__(self.__describe_certificates__, self.certificates)
        self.__threading_call__(self.__list_tags_for_certificate__, self.certificates)

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
                                id=certificate["CertificateArn"].split("/")[-1],
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

    def __describe_certificates__(self, certificate):
        try:
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

    def __list_tags_for_certificate__(self, certificate):
        try:
            regional_client = self.regional_clients[certificate.region]
            response = regional_client.list_tags_for_certificate(
                CertificateArn=certificate.arn
            )["Tags"]
            certificate.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Certificate(BaseModel):
    arn: str
    name: str
    id: str
    type: str
    tags: Optional[list] = []
    expiration_days: int
    transparency_logging: Optional[bool]
    region: str
