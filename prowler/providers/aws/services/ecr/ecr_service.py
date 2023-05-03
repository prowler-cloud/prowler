import threading
from json import loads
from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ ECR
class ECR:
    def __init__(self, audit_info):
        self.service = "ecr"
        self.session = audit_info.audit_session
        self.audit_resources = audit_info.audit_resources
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.repositories = []
        self.registries = []
        self.__threading_call__(self.__describe_repositories__)
        self.__describe_repository_policies__()
        self.__get_image_details__()
        self.__get_repository_lifecycle_policy__()
        self.__threading_call__(self.__get_registry_scanning_configuration__)
        self.__list_tags_for_resource__()

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

    def __describe_repositories__(self, regional_client):
        logger.info("ECR - Describing repositories...")
        try:
            describe_ecr_paginator = regional_client.get_paginator(
                "describe_repositories"
            )
            for page in describe_ecr_paginator.paginate():
                for repository in page["repositories"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            repository["repositoryArn"], self.audit_resources
                        )
                    ):
                        self.repositories.append(
                            Repository(
                                name=repository["repositoryName"],
                                arn=repository["repositoryArn"],
                                region=regional_client.region,
                                scan_on_push=repository["imageScanningConfiguration"][
                                    "scanOnPush"
                                ],
                                policy=None,
                                images_details=[],
                                lifecycle_policy=None,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_repository_policies__(self):
        logger.info("ECR - Describing repository policies...")
        try:
            for repository in self.repositories:
                client = self.regional_clients[repository.region]
                policy = client.get_repository_policy(repositoryName=repository.name)
                if "policyText" in policy:
                    repository.policy = loads(policy["policyText"])

        except Exception as error:
            if "RepositoryPolicyNotFoundException" not in str(error):
                logger.error(
                    f"-- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_repository_lifecycle_policy__(self):
        logger.info("ECR - Getting repository lifecycle policy...")
        try:
            for repository in self.repositories:
                client = self.regional_clients[repository.region]
                policy = client.get_lifecycle_policy(repositoryName=repository.name)
                if "lifecyclePolicyText" in policy:
                    repository.lifecycle_policy = policy["lifecyclePolicyText"]

        except Exception as error:
            if "LifecyclePolicyNotFoundException" not in str(error):
                logger.error(
                    f"-- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_image_details__(self):
        logger.info("ECR - Getting images details...")
        try:
            for repository in self.repositories:
                # if the repo is not scanning pushed images there is nothing to do
                if repository.scan_on_push:
                    client = self.regional_clients[repository.region]
                    describe_images_paginator = client.get_paginator("describe_images")
                    for page in describe_images_paginator.paginate(
                        repositoryName=repository.name
                    ):
                        for image in page["imageDetails"]:
                            severity_counts = None
                            last_scan_status = None
                            if "imageScanStatus" in image:
                                last_scan_status = image["imageScanStatus"]["status"]

                            if "imageScanFindingsSummary" in image:
                                severity_counts = FindingSeverityCounts(
                                    critical=0, high=0, medium=0
                                )
                                finding_severity_counts = image[
                                    "imageScanFindingsSummary"
                                ]["findingSeverityCounts"]
                                if "CRITICAL" in finding_severity_counts:
                                    severity_counts.critical = finding_severity_counts[
                                        "CRITICAL"
                                    ]
                                if "HIGH" in finding_severity_counts:
                                    severity_counts.high = finding_severity_counts[
                                        "HIGH"
                                    ]
                                if "MEDIUM" in finding_severity_counts:
                                    severity_counts.medium = finding_severity_counts[
                                        "MEDIUM"
                                    ]
                            latest_tag = "None"
                            if image.get("imageTags"):
                                latest_tag = image["imageTags"][0]
                            repository.images_details.append(
                                ImageDetails(
                                    latest_tag=latest_tag,
                                    latest_digest=image["imageDigest"],
                                    scan_findings_status=last_scan_status,
                                    scan_findings_severity_count=severity_counts,
                                )
                            )

        except Exception as error:
            logger.error(
                f"-- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __list_tags_for_resource__(self):
        logger.info("ECR - List Tags...")
        try:
            for repository in self.repositories:
                try:
                    regional_client = self.regional_clients[repository.region]
                    response = regional_client.list_tags_for_resource(
                        resourceArn=repository.arn
                    )["tags"]
                    repository.tags = response

                except ClientError as error:
                    if error.response["Error"]["Code"] == "RepositoryNotFoundException":
                        logger.warning(
                            f"{regional_client.region} --"
                            f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                            f" {error}"
                        )
                        continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_registry_scanning_configuration__(self, regional_client):
        logger.info("ECR - Getting Registry Scanning Configuration...")
        try:
            response = regional_client.get_registry_scanning_configuration()
            rules = []
            for rule in response.get("scanningConfiguration").get("rules", []):
                rules.append(
                    ScanningRule(
                        scan_frequency=rule.get("scanFrequency"),
                        scan_filters=rule.get("repositoryFilters"),
                    )
                )
            self.registries.append(
                Registry(
                    id=response.get("registryId", ""),
                    scan_type=response.get("scanningConfiguration").get(
                        "scanType", "BASIC"
                    ),
                    region=regional_client.region,
                    rules=rules,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class FindingSeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int


class ImageDetails(BaseModel):
    latest_tag: str
    latest_digest: str
    scan_findings_status: Optional[str]
    scan_findings_severity_count: Optional[FindingSeverityCounts]


class Repository(BaseModel):
    name: str
    arn: str
    region: str
    scan_on_push: bool
    policy: Optional[dict]
    images_details: Optional[list[ImageDetails]]
    lifecycle_policy: Optional[str]
    tags: Optional[list] = []


class ScanningRule(BaseModel):
    scan_frequency: str
    scan_filters: list[dict]


class Registry(BaseModel):
    id: str
    region: str
    scan_type: str
    rules: list[ScanningRule]
    tags: Optional[list] = []
