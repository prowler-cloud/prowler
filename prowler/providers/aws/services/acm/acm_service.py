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
        self.certificates = {}
        self.__threading_call__(self._list_certificates)
        self.__threading_call__(self._describe_certificates, self.certificates.values())
        self.__threading_call__(
            self._list_tags_for_certificate, self.certificates.values()
        )

    def _list_certificates(self, regional_client):
        logger.info("ACM - Listing Certificates...")
        try:
            includes = {
                "keyTypes": [
                    "RSA_1024",
                    "RSA_2048",
                    "RSA_3072",
                    "RSA_4096",
                    "EC_prime256v1",
                    "EC_secp384r1",
                    "EC_secp521r1",
                ]
            }
            list_certificates_paginator = regional_client.get_paginator(
                "list_certificates"
            )
            for page in list_certificates_paginator.paginate(Includes=includes):
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
                        self.certificates[certificate["CertificateArn"]] = Certificate(
                            arn=certificate["CertificateArn"],
                            name=certificate["DomainName"],
                            id=certificate["CertificateArn"].split("/")[-1],
                            type=certificate["Type"],
                            key_algorithm=certificate["KeyAlgorithm"],
                            expiration_days=certificate_expiration_time,
                            in_use=certificate.get("InUse", False),
                            transparency_logging=False,
                            region=regional_client.region,
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_certificates(self, certificate):
        logger.info("ACM - Describing Certificates...")
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
                f"{certificate.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_certificate(self, certificate):
        logger.info("ACM - List Tags...")
        try:
            regional_client = self.regional_clients[certificate.region]
            response = regional_client.list_tags_for_certificate(
                CertificateArn=certificate.arn
            )["Tags"]
            certificate.tags = response
        except Exception as error:
            logger.error(
                f"{certificate.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Certificate(BaseModel):
    arn: str
    name: str
    id: str
    type: str
    key_algorithm: str
    tags: Optional[list] = []
    expiration_days: int
    in_use: bool
    transparency_logging: Optional[bool]
    region: str
