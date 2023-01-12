import threading
from dataclasses import dataclass

from prowler.config.config import timestamp_utc
from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## ACM
class ACM:
    def __init__(self, audit_info):
        self.service = "acm"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.certificates = []
        self.__threading_call__(self.__list_certificates__)
        self.__describe_certificates__()

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
                for analyzer in page["CertificateSummaryList"]:
                    self.certificates.append(
                        Certificate(
                            analyzer["CertificateArn"],
                            analyzer["DomainName"],
                            False,
                            regional_client.region,
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
                certificate.type = response["Type"]
                if "NotAfter" in response:
                    certificate.expiration_days = (
                        response["NotAfter"] - timestamp_utc
                    ).days
                else:
                    certificate.expiration_days = 0
                if (
                    response["Options"]["CertificateTransparencyLoggingPreference"]
                    == "ENABLED"
                ):
                    certificate.transparency_logging = True
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class Certificate:
    arn: str
    name: str
    type: str
    expiration_days: int
    transparency_logging: bool
    region: str

    def __init__(
        self,
        arn,
        name,
        transparency_logging,
        region,
    ):
        self.arn = arn
        self.name = name
        self.transparency_logging = transparency_logging
        self.region = region
