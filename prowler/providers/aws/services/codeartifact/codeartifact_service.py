import threading
from enum import Enum

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## CodeArtifact
class CodeArtifact:
    def __init__(self, audit_info):
        self.service = "codeartifact"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        # repositories is a dictionary containing all the codeartifact service information
        self.repositories = {}
        self.__threading_call__(self.__list_repositories__)
        self.__threading_call__(self.__list_packages__)

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

    def __list_repositories__(self, regional_client):
        logger.info("CodeArtifact - Listing Repositories...")
        try:
            list_repositories_paginator = regional_client.get_paginator(
                "list_repositories"
            )
            for page in list_repositories_paginator.paginate():
                for repository in page["repositories"]:
                    package_name = repository["name"]
                    package_domain_name = repository["domainName"]
                    package_domain_owner = repository["domainOwner"]
                    package_arn = repository["arn"]
                    # Save Repository
                    self.repositories[package_name] = Repository(
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

    def __list_packages__(self, regional_client):
        logger.info("CodeArtifact - Listing Packages and retrieving information...")
        try:
            for repository in self.repositories:
                if self.repositories[repository].region == regional_client.region:
                    list_packages_paginator = regional_client.get_paginator(
                        "list_packages"
                    )
                    list_packages_parameters = {
                        "domain": self.repositories[repository].domain_name,
                        "domainOwner": self.repositories[repository].domain_owner,
                        "repository": repository,
                    }
                    packages = []
                    for page in list_packages_paginator.paginate(
                        **list_packages_parameters
                    ):
                        for package in page["packages"]:
                            # Package information
                            package_format = package["format"]
                            package_namespace = package["namespace"]
                            package_name = package["package"]
                            package_origin_configuration_restrictions_publish = package[
                                "originConfiguration"
                            ]["restrictions"]["publish"]
                            package_origin_configuration_restrictions_upstream = (
                                package["originConfiguration"]["restrictions"][
                                    "upstream"
                                ]
                            )
                            # Get Latest Package Version
                            latest_version_information = (
                                regional_client.list_package_versions(
                                    domain=self.repositories[repository].domain_name,
                                    domainOwner=self.repositories[
                                        repository
                                    ].domain_owner,
                                    repository=repository,
                                    format=package_format,
                                    namespace=package_namespace,
                                    package=package_name,
                                    short_by="PUBLISHED_TIME",
                                )
                            )
                            latest_version = latest_version_information["versions"][0][
                                "version"
                            ]
                            latest_origin_type = latest_version_information["versions"][
                                0
                            ]["origin"]["originType"]
                            latest_status = latest_version_information["versions"][0][
                                "status"
                            ]

                            packages.append(
                                Package(
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
                                        origin=OriginInformation(
                                            origin_type=latest_origin_type
                                        ),
                                    ),
                                )
                            )
                    # Save all the packages information
                    self.repositories[repository].packages = packages

        except Exception as error:
            logger.error(
                f"{regional_client.region} --"
                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                f" {error}"
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
    """Possibel values for the package status"""

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
    namespace: str
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
