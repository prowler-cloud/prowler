from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################## Macie
class Macie(AWSService):
    def __init__(self, audit_info):
        # Call AWSService's __init__
        super().__init__("macie2", audit_info)
        self.sessions = []
        self.__threading_call__(self.__get_macie_session__)

    def __get_session_arn_template__(self, region):
        return f"arn:{self.audited_partition}:macie:{region}:{self.audited_account}:session"

    def __get_macie_session__(self, regional_client):
        logger.info("Macie - Get Macie Session...")
        try:
            self.sessions.append(
                Session(
                    status=regional_client.get_macie_session()["status"],
                    region=regional_client.region,
                )
            )

        except Exception as error:
            if "Macie is not enabled" in str(error):
                self.sessions.append(
                    Session(
                        status="DISABLED",
                        region=regional_client.region,
                    )
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class Session(BaseModel):
    status: str
    region: str
