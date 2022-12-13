import threading
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ TrustedAdvisor
class TrustedAdvisor:
    def __init__(self, audit_info):
        self.service = "support"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.checks = []
        self.__threading_call__(self.__describe_trusted_advisor_checks__)
        self.__threading_call__(self.__describe_trusted_advisor_check_result__)

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

    def __describe_trusted_advisor_checks__(self, regional_client):
        logger.info("TrustedAdvisor - Describing Checks...")
        try:
            for check in regional_client.describe_trusted_advisor_checks(language="en")[
                "checks"
            ]:
                self.checks.append(
                    Check(
                        id=check["id"],
                        name=check["name"],
                        region=regional_client.region,
                    )
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_trusted_advisor_check_result__(self, regional_client):
        logger.info("TrustedAdvisor - Describing Check Result...")
        try:
            for check in self.checks:
                if check.region == regional_client.region:
                    response = regional_client.describe_trusted_advisor_check_result(
                        checkId=check.id
                    )
                    if "result" in response:
                        check.status = response["result"]["status"]
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Check(BaseModel):
    id: str
    name: str
    status: Optional[str]
    region: str
