from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


################## Macie
class Macie(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__("macie2", provider)
        self.sessions = []
        self.__threading_call__(self._get_macie_session)
        self.__threading_call__(
            self._get_automated_discovery_configuration, self.sessions
        )

    def _get_session_arn_template(self, region):
        return f"arn:{self.audited_partition}:macie:{region}:{self.audited_account}:session"

    def _get_macie_session(self, regional_client):
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

    def _get_automated_discovery_configuration(self, session):
        logger.info("Macie - Get Automated Discovery Configuration...")
        try:
            if session.status == "ENABLED":
                regional_client = self.regional_clients[session.region]
                session.automated_discovery_status = (
                    regional_client.get_automated_discovery_configuration().get(
                        "status", "DISABLED"
                    )
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Session(BaseModel):
    status: str
    automated_discovery_status: str = "DISABLED"
    region: str
