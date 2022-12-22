import threading
from dataclasses import dataclass
from json import loads

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################################ ECR
class ECR:
    def __init__(self, audit_info):
        self.service = "ecr"
        self.session = audit_info.audit_session
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.repositories = []
        self.__threading_call__(self.__describe_repositories__)
        self.__describe_repository_policies__()
        self.__get_image_details__()
        self.__get_repository_lifecycle_policy__()

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
                            lyfecicle_policy=None,
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
                    repository.lyfecicle_policy = policy["lifecyclePolicyText"]

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


@dataclass
class FindingSeverityCounts:
    critical: int
    high: int
    medium: int

    def __init__(
        self,
        critical,
        high,
        medium,
    ):
        self.critical = critical
        self.high = high
        self.medium = medium


@dataclass
class ImageDetails:
    latest_tag: str
    latest_digest: str
    scan_findings_status: str
    scan_findings_severity_count: FindingSeverityCounts

    def __init__(
        self,
        latest_tag,
        latest_digest,
        scan_findings_status,
        scan_findings_severity_count,
    ):
        self.latest_tag = latest_tag
        self.latest_digest = latest_digest
        self.scan_findings_status = scan_findings_status
        self.scan_findings_severity_count = scan_findings_severity_count


@dataclass
class Repository:
    name: str
    arn: str
    region: str
    scan_on_push: bool
    policy: dict
    images_details: list[ImageDetails]
    lyfecicle_policy: str

    def __init__(
        self, name, arn, region, scan_on_push, policy, images_details, lyfecicle_policy
    ):
        self.name = name
        self.arn = arn
        self.region = region
        self.scan_on_push = scan_on_push
        self.policy = policy
        self.images_details = images_details
        self.lyfecicle_policy = lyfecicle_policy
