from datetime import datetime
from json import loads
from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################################ ECR
class ECR(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.registry_id = self.audited_account
        self.registries = {}
        self.__threading_call__(self._describe_registries_and_repositories)
        self.__threading_call__(self._describe_repository_policies)
        self.__threading_call__(self._get_image_details)
        self.__threading_call__(self._get_repository_lifecycle_policy)
        self.__threading_call__(self._get_registry_scanning_configuration)
        self.__threading_call__(self._list_tags_for_resource)

    def _describe_registries_and_repositories(self, regional_client):
        logger.info("ECR - Describing registries and repositories...")
        regional_registry_repositories = []
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
                        regional_registry_repositories.append(
                            Repository(
                                name=repository["repositoryName"],
                                arn=repository["repositoryArn"],
                                registry_id=repository["registryId"],
                                region=regional_client.region,
                                scan_on_push=repository["imageScanningConfiguration"][
                                    "scanOnPush"
                                ],
                                immutability=repository.get(
                                    "imageTagMutability", "MUTABLE"
                                ),
                                policy=None,
                                images_details=[],
                                lifecycle_policy=None,
                            )
                        )
            # The default ECR registry is assumed
            self.registries[regional_client.region] = Registry(
                id=self.registry_id,
                arn=f"arn:{self.audited_partition}:ecr:{regional_client.region}:{self.audited_account}:registry/{self.registry_id}",
                region=regional_client.region,
                repositories=regional_registry_repositories,
            )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_repository_policies(self, regional_client):
        logger.info("ECR - Describing repository policies...")
        try:
            if regional_client.region in self.registries:
                for repository in self.registries[regional_client.region].repositories:
                    client = self.regional_clients[repository.region]
                    try:
                        policy = client.get_repository_policy(
                            repositoryName=repository.name
                        )
                        if "policyText" in policy:
                            repository.policy = loads(policy["policyText"])
                    except ClientError as error:
                        if (
                            error.response["Error"]["Code"]
                            == "RepositoryPolicyNotFoundException"
                        ):
                            logger.warning(
                                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )

        except Exception as error:
            if "RepositoryPolicyNotFoundException" not in str(error):
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_repository_lifecycle_policy(self, regional_client):
        logger.info("ECR - Getting repository lifecycle policy...")
        try:
            if regional_client.region in self.registries:
                for repository in self.registries[regional_client.region].repositories:
                    client = self.regional_clients[repository.region]
                    try:
                        policy = client.get_lifecycle_policy(
                            repositoryName=repository.name
                        )
                        if "lifecyclePolicyText" in policy:
                            repository.lifecycle_policy = policy["lifecyclePolicyText"]
                    except ClientError as error:
                        if (
                            error.response["Error"]["Code"]
                            == "LifecyclePolicyNotFoundException"
                        ):
                            logger.warning(
                                f"{regional_client.region} --"
                                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                                f" {error}"
                            )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_image_details(self, regional_client):
        logger.info("ECR - Getting images details...")
        try:
            if regional_client.region in self.registries:
                for repository in self.registries[regional_client.region].repositories:
                    # There is nothing to do if the repository is not scanning pushed images
                    if repository.scan_on_push:
                        client = self.regional_clients[repository.region]
                        describe_images_paginator = client.get_paginator(
                            "describe_images"
                        )
                        for page in describe_images_paginator.paginate(
                            registryId=self.registries[regional_client.region].id,
                            repositoryName=repository.name,
                            PaginationConfig={"PageSize": 1000},
                        ):
                            for image in page["imageDetails"]:
                                # The following condition is required since sometimes
                                # the AWS ECR API returns None using the iterator
                                if image is not None:
                                    artifact_media_type = image.get(
                                        "artifactMediaType", None
                                    )
                                    tags = image.get("imageTags", [])
                                    if ECR._is_artifact_scannable(
                                        artifact_media_type, tags
                                    ):
                                        severity_counts = None
                                        last_scan_status = None
                                        image_digest = image.get("imageDigest")
                                        latest_tag = image.get("imageTags", ["None"])[0]
                                        image_pushed_at = image.get("imagePushedAt")
                                        image_scan_findings_field_name = (
                                            "imageScanFindingsSummary"
                                        )
                                        if "docker" in artifact_media_type:
                                            type = "Docker"
                                        elif "oci" in artifact_media_type:
                                            type = "OCI"
                                        else:
                                            type = ""

                                        # If imageScanStatus is not present or imageScanFindingsSummary is missing,
                                        # we need to call DescribeImageScanFindings because AWS' new version of
                                        # basic scanning does not support imageScanFindingsSummary and imageScanStatus
                                        # in the DescribeImages API.
                                        if "imageScanStatus" not in image:
                                            try:
                                                # use "image" for scan findings to get data the same way as for an image
                                                image = (
                                                    client.describe_image_scan_findings(
                                                        registryId=self.registries[
                                                            regional_client.region
                                                        ].id,
                                                        repositoryName=repository.name,
                                                        imageId={
                                                            "imageDigest": image_digest
                                                        },
                                                    )
                                                )
                                                image_scan_findings_field_name = (
                                                    "imageScanFindings"
                                                )
                                            except (
                                                client.exceptions.ImageNotFoundException
                                            ) as error:
                                                logger.warning(
                                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                                )
                                                continue
                                            except (
                                                client.exceptions.ScanNotFoundException
                                            ) as error:
                                                logger.warning(
                                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                                )
                                                continue
                                            except Exception as error:
                                                logger.error(
                                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                                )
                                                continue

                                        if "imageScanStatus" in image:
                                            last_scan_status = image["imageScanStatus"][
                                                "status"
                                            ]

                                        if image_scan_findings_field_name in image:
                                            severity_counts = FindingSeverityCounts(
                                                critical=0, high=0, medium=0
                                            )
                                            finding_severity_counts = image[
                                                image_scan_findings_field_name
                                            ].get("findingSeverityCounts", {})
                                            severity_counts.critical = (
                                                finding_severity_counts.get(
                                                    "CRITICAL", 0
                                                )
                                            )
                                            severity_counts.high = (
                                                finding_severity_counts.get("HIGH", 0)
                                            )
                                            severity_counts.medium = (
                                                finding_severity_counts.get("MEDIUM", 0)
                                            )

                                        repository.images_details.append(
                                            ImageDetails(
                                                latest_tag=latest_tag,
                                                image_pushed_at=image_pushed_at,
                                                latest_digest=image_digest,
                                                scan_findings_status=last_scan_status,
                                                scan_findings_severity_count=severity_counts,
                                                artifact_media_type=artifact_media_type,
                                                type=type,
                                            )
                                        )
                        # Sort the repository images by date pushed
                        repository.images_details.sort(
                            key=lambda image: image.image_pushed_at
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, regional_client):
        logger.info("ECR - List Tags...")
        try:
            if regional_client.region in self.registries:
                for repository in self.registries[regional_client.region].repositories:
                    try:
                        regional_client = self.regional_clients[repository.region]
                        response = regional_client.list_tags_for_resource(
                            resourceArn=repository.arn
                        )["tags"]
                        repository.tags = response

                    except ClientError as error:
                        if (
                            error.response["Error"]["Code"]
                            == "RepositoryNotFoundException"
                        ):
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

    def _get_registry_scanning_configuration(self, regional_client):
        logger.info("ECR - Getting Registry Scanning Configuration...")
        try:
            if regional_client.region in self.registries:
                response = regional_client.get_registry_scanning_configuration()
                rules = []
                for rule in response.get("scanningConfiguration").get("rules", []):
                    rules.append(
                        ScanningRule(
                            scan_frequency=rule.get("scanFrequency"),
                            scan_filters=rule.get("repositoryFilters", []),
                        )
                    )

                self.registries[regional_client.region].scan_type = response.get(
                    "scanningConfiguration"
                ).get("scanType", "BASIC")
                self.registries[regional_client.region].rules = rules
        except ClientError as error:
            if error.response["Error"][
                "Code"
            ] == "ValidationException" and "GetRegistryScanningConfiguration operation: This feature is disabled" in str(
                error
            ):
                self.registries[regional_client.region].scan_type = "BASIC"
                self.registries[regional_client.region].rules = []
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def _is_artifact_scannable(artifact_media_type: str, tags: list[str] = []) -> bool:
        """
        Check if an artifact is scannable based on its media type and tags.

        Args:
            artifact_media_type (str): The media type of the artifact.
            tags (list): The list of tags associated with the artifact.

        Returns:
            bool: True if the artifact is scannable, False otherwise.
        """
        try:
            if artifact_media_type is None:
                return False

            # Tools like GoogleContainerTools/jib uses `application/vnd.oci.image.config.v1+json`` also for signatures, which are not scannable.
            # Luckily, these are tagged with sha-<HASH-CODE>.sig, so that they can still be easily recognized.
            for tag in tags:
                if tag.startswith("sha256-") and tag.endswith(".sig"):
                    return False

            scannable_artifact_media_types = [
                "application/vnd.docker.container.image.v1+json",  # Docker image configuration
                "application/vnd.docker.image.rootfs.diff.tar",  # Docker image layer as a tar archive
                "application/vnd.docker.image.rootfs.diff.tar.gzip",  # Docker image layer that is compressed using gzip
                "application/vnd.oci.image.config.v1+json",  # OCI image configuration, but also used by GoogleContainerTools/jib for signatures
                "application/vnd.oci.image.layer.v1.tar",  # Uncompressed OCI image layer
                "application/vnd.oci.image.layer.v1.tar+gzip",  # Compressed OCI image layer
            ]

            return artifact_media_type in scannable_artifact_media_types
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False


class FindingSeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int


class ImageDetails(BaseModel):
    latest_tag: str
    latest_digest: str
    image_pushed_at: datetime
    scan_findings_status: Optional[str]
    scan_findings_severity_count: Optional[FindingSeverityCounts]
    artifact_media_type: Optional[str]
    type: str


class Repository(BaseModel):
    name: str
    arn: str
    region: str
    registry_id = str
    scan_on_push: bool
    immutability: Optional[str]
    policy: Optional[dict]
    images_details: Optional[list[ImageDetails]]
    lifecycle_policy: Optional[str]
    tags: Optional[list] = []


class ScanningRule(BaseModel):
    scan_frequency: str
    scan_filters: list[dict]


class Registry(BaseModel):
    id: str
    arn: str
    region: str
    repositories: list[Repository]
    scan_type: Optional[str]
    rules: Optional[list[ScanningRule]]
