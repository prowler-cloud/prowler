from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## AccessAnalyzer
class AccessAnalyzer(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.analyzers = []
        self.__threading_call__(self.__list_analyzers__)
        self.__list_findings__()
        self.__get_finding_status__()

    def __list_analyzers__(self, regional_client):
        logger.info("AccessAnalyzer - Listing Analyzers...")
        try:
            list_analyzers_paginator = regional_client.get_paginator("list_analyzers")
            analyzer_count = 0
            for page in list_analyzers_paginator.paginate():
                for analyzer in page["analyzers"]:
                    if not self.audit_resources or (
                        is_resource_filtered(analyzer["arn"], self.audit_resources)
                    ):
                        analyzer_count += 1
                        self.analyzers.append(
                            Analyzer(
                                arn=analyzer["arn"],
                                name=analyzer["name"],
                                status=analyzer["status"],
                                tags=[analyzer.get("tags")],
                                type=analyzer["type"],
                                region=regional_client.region,
                            )
                        )
            # No analyzers in region
            if analyzer_count == 0:
                self.analyzers.append(
                    Analyzer(
                        arn=self.audited_account_arn,
                        name=self.audited_account,
                        status="NOT_AVAILABLE",
                        tags=[],
                        type="",
                        region=regional_client.region,
                    )
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_finding_status__(self):
        logger.info("AccessAnalyzer - Get Finding status...")
        try:
            for analyzer in self.analyzers:
                if analyzer.status == "ACTIVE":
                    regional_client = self.regional_clients[analyzer.region]
                    for finding in analyzer.findings:
                        try:
                            finding_information = regional_client.get_finding(
                                analyzerArn=analyzer.arn, id=finding.id
                            )
                            finding.status = finding_information["finding"]["status"]
                        except ClientError as error:
                            if (
                                error.response["Error"]["Code"]
                                == "ResourceNotFoundException"
                            ):
                                logger.warning(
                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                                finding.status = ""
                            continue

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_findings__(self):
        logger.info("AccessAnalyzer - Listing Findings per Analyzer...")
        try:
            for analyzer in self.analyzers:
                if analyzer.status == "ACTIVE":
                    regional_client = self.regional_clients[analyzer.region]
                    list_findings_paginator = regional_client.get_paginator(
                        "list_findings"
                    )
                    for page in list_findings_paginator.paginate(
                        analyzerArn=analyzer.arn
                    ):
                        for finding in page["findings"]:
                            analyzer.findings.append(Finding(id=finding["id"]))

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Finding(BaseModel):
    id: str
    status: str = ""


class Analyzer(BaseModel):
    arn: str
    name: str
    status: str
    findings: list[Finding] = []
    tags: Optional[list] = []
    type: str
    region: str
