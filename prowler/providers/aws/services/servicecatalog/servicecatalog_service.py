from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService

PORTFOLIO_SHARE_TYPES = [
    "ACCOUNT",
    "ORGANIZATION",
    "ORGANIZATIONAL_UNIT",
    "ORGANIZATION_MEMBER_ACCOUNT",
]


class ServiceCatalog(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.portfolios = {}
        self.__threading_call__(self._list_portfolios)
        self.__threading_call__(
            self._describe_portfolio_shares, self.portfolios.values()
        )
        self.__threading_call__(self._describe_portfolio, self.portfolios.values())

    def _list_portfolios(self, regional_client):
        logger.info("ServiceCatalog - listing portfolios...")
        try:
            response = regional_client.list_portfolios()
            for portfolio in response["PortfolioDetails"]:
                portfolio_arn = portfolio["ARN"]
                if not self.audit_resources or (
                    is_resource_filtered(portfolio_arn, self.audit_resources)
                ):
                    self.portfolios[portfolio_arn] = Portfolio(
                        arn=portfolio_arn,
                        id=portfolio["Id"],
                        name=portfolio["DisplayName"],
                        region=regional_client.region,
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_portfolio_shares(self, portfolio):
        try:
            logger.info("ServiceCatalog - describing portfolios shares...")
            regional_client = self.regional_clients[portfolio.region]
            for portfolio_type in PORTFOLIO_SHARE_TYPES:
                try:
                    for share in regional_client.describe_portfolio_shares(
                        PortfolioId=portfolio.id,
                        Type=portfolio_type,
                    ).get("PortfolioShareDetails", []):
                        portfolio_share = PortfolioShare(
                            type=portfolio_type,
                            accepted=share["Accepted"],
                        )
                        portfolio.shares.append(portfolio_share)
                except Exception as error:
                    if error.response["Error"]["Code"] == "AccessDeniedException":
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                        portfolio.shares = None
                    else:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_portfolio(self, portfolio):
        try:
            logger.info("ServiceCatalog - describing portfolios...")
            try:
                regional_client = self.regional_clients[portfolio.region]
                portfolio.tags = regional_client.describe_portfolio(
                    Id=portfolio.id,
                )["Tags"]
            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class PortfolioShare(BaseModel):
    type: str
    accepted: bool


class Portfolio(BaseModel):
    id: str
    name: str
    arn: str
    region: str
    shares: Optional[list[PortfolioShare]] = []
    tags: Optional[list] = []
