from enum import Enum
from typing import Iterator, Optional, Tuple

from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.check.resource_limit import (
    get_resource_scan_limit,
    iter_limited_paginator_items,
)
from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class CodeArtifact(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        # repositories is a dictionary containing all the codeartifact service information
        self.repositories = {}
        # repository ARNs whose selected packages have been listed and memoized
        # into repository.packages.
        self._packages_listed = set()
        self.package_limit = get_resource_scan_limit(
            self.audit_config, "max_codeartifact_packages"
        )
        self.__threading_call__(self._list_repositories)
        for _ in self._load_packages_for_analysis():
            pass
        self._list_tags_for_resource()

    def _list_repositories(self, regional_client):
        logger.info("CodeArtifact - Listing Repositories...")
        try:
            list_repositories_paginator = regional_client.get_paginator(
                "list_repositories"
            )
            for page in list_repositories_paginator.paginate():
                for repository in page["repositories"]:
                    if not self.audit_resources or (
                        is_resource_filtered(repository["arn"], self.audit_resources)
                    ):
                        package_name = repository["name"]
                        package_domain_name = repository["domainName"]
                        package_domain_owner = repository["domainOwner"]
                        package_arn = repository["arn"]
                        # Save Repository
                        # We must use the Package ARN as the dict key to have unique keys
                        self.repositories[package_arn] = Repository(
                            name=package_name,
                            arn=package_arn,
                            domain_name=package_domain_name,
                            domain_owner=package_domain_owner,
                            region=regional_client.region,
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def _iter_repository_packages(
        self, repository, limit: Optional[int] = None
    ) -> Iterator["Package"]:
        """Yield packages for a single repository, hydrating each one lazily.

        Each package requires an extra ``list_package_versions`` call to
        resolve its latest version, so producing them lazily lets the resource
        limit stop before extra package version calls.
        """
        regional_client = self.regional_clients[repository.region]
        try:
            list_packages_paginator = regional_client.get_paginator("list_packages")
            list_packages_parameters = {
                "domain": repository.domain_name,
                "domainOwner": repository.domain_owner,
                "repository": repository.name,
            }
            for package in iter_limited_paginator_items(
                list_packages_paginator,
                "packages",
                limit,
                **list_packages_parameters,
            ):
                # Package information
                package_format = package["format"]
                package_namespace = package.get("namespace")
                package_name = package["package"]
                package_origin_configuration_restrictions_publish = package[
                    "originConfiguration"
                ]["restrictions"]["publish"]
                package_origin_configuration_restrictions_upstream = package[
                    "originConfiguration"
                ]["restrictions"]["upstream"]
                # Get Latest Package Version
                list_package_versions_parameters = {
                    "domain": repository.domain_name,
                    "domainOwner": repository.domain_owner,
                    "repository": repository.name,
                    "format": package_format,
                    "package": package_name,
                    "sortBy": "PUBLISHED_TIME",
                    "maxResults": 1,
                }
                if package_namespace:
                    list_package_versions_parameters["namespace"] = package_namespace
                latest_version_information = regional_client.list_package_versions(
                    **list_package_versions_parameters
                )
                latest_version = ""
                latest_origin_type = "UNKNOWN"
                latest_status = "Published"
                if latest_version_information.get("versions"):
                    latest_version = latest_version_information["versions"][0].get(
                        "version"
                    )
                    latest_origin_type = (
                        latest_version_information["versions"][0]
                        .get("origin", {})
                        .get("originType", "UNKNOWN")
                    )
                    latest_status = latest_version_information["versions"][0].get(
                        "status", "Published"
                    )

                yield Package(
                    name=package_name,
                    namespace=package_namespace,
                    format=package_format,
                    origin_configuration=OriginConfiguration(
                        restrictions=Restrictions(
                            publish=package_origin_configuration_restrictions_publish,
                            upstream=package_origin_configuration_restrictions_upstream,
                        )
                    ),
                    latest_version=LatestPackageVersion(
                        version=latest_version,
                        status=latest_status,
                        origin=OriginInformation(origin_type=latest_origin_type),
                    ),
                )

        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.warning(
                    f"{repository.region} --"
                    f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                    f" {error}"
                )
            else:
                logger.error(
                    f"{repository.region} --"
                    f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                    f" {error}"
                )
        except Exception as error:
            logger.error(
                f"{repository.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
            )

    def _load_packages_for_analysis(self) -> Iterator[Tuple["Repository", "Package"]]:
        """Yield the ``(repository, package)`` pairs selected for analysis.

        Package listing stays in the service layer so checks receive only the
        selected packages and remain unaware of resource-analysis limits.
        """
        yielded = 0
        for repository in list(self.repositories.values()):
            if repository.arn in self._packages_listed:
                for package in repository.packages:
                    yield repository, package
                    yielded += 1
                    if self.package_limit and yielded >= self.package_limit:
                        return
                continue
            collected = []
            remaining_limit = None
            if self.package_limit:
                remaining_limit = self.package_limit - yielded
                if remaining_limit <= 0:
                    return
            for package in self._iter_repository_packages(repository, remaining_limit):
                collected.append(package)
                repository.packages = collected
                yield repository, package
                yielded += 1
                if self.package_limit and yielded >= self.package_limit:
                    self._packages_listed.add(repository.arn)
                    return
            self._packages_listed.add(repository.arn)

    def _list_tags_for_resource(self):
        logger.info("CodeArtifact - List Tags...")
        try:
            for repository in self.repositories.values():
                regional_client = self.regional_clients[repository.region]
                response = regional_client.list_tags_for_resource(
                    resourceArn=repository.arn
                )["tags"]
                repository.tags = response
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class RestrictionValues(Enum):
    """Possible values for the package origin restriction"""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class Restrictions(BaseModel):
    """Information about the upstream and publish package origin restrictions"""

    publish: RestrictionValues
    upstream: RestrictionValues


class OriginConfiguration(BaseModel):
    """Details about the package origin configuration of a package"""

    restrictions: Restrictions


class OriginInformationValues(Enum):
    """Possible values for the OriginInformation"""

    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"
    UNKNOWN = "UNKNOWN"


class OriginInformation(BaseModel):
    """
    Describes how the package version was originally added to the domain.

    An INTERNAL origin type means the package version was published directly to a repository in the domain.

    An EXTERNAL origin type means the package version was ingested from an external connection.
    """

    origin_type: OriginInformationValues


class LatestPackageVersionStatus(Enum):
    """Possible values for the package status"""

    Published = "Published"
    Unfinished = "Unfinished"
    Unlisted = "Unlisted"
    Archived = "Archived"
    Disposed = "Disposed"
    Deleted = "Deleted"


class LatestPackageVersion(BaseModel):
    """Details of the latest package version"""

    version: str
    status: LatestPackageVersionStatus
    origin: OriginInformation


class Package(BaseModel):
    """Details of a package"""

    name: str
    namespace: Optional[str] = None
    format: str
    origin_configuration: OriginConfiguration
    latest_version: LatestPackageVersion


class Repository(BaseModel):
    """Information about a Repository"""

    name: str
    arn: str
    domain_name: str
    domain_owner: str
    packages: list[Package] = []
    region: str
    tags: Optional[list] = []
