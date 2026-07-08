from typing import Generator, Optional, Tuple

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.lib.service.service import AWSService


class CodeCommit(AWSService):
    """AWS CodeCommit service class for managing repository resources.

    This class handles interactions with AWS CodeCommit service, including
    listing repositories and retrieving their metadata (default branch and
    the commit it currently points to). The actual file content of a
    repository is fetched lazily, on demand, via `get_repository_files_content`,
    since walking a repository tree and downloading every blob can be an
    expensive operation.

    Attributes:
        repositories: Dictionary mapping repository ARNs to Repository objects.
    """

    def __init__(self, provider):
        """Initializes the CodeCommit service class.

        Args:
            provider: AWS provider instance for making API calls.
        """
        super().__init__(__class__.__name__, provider)
        self.repositories = {}
        self.__threading_call__(self._list_repositories)
        if self.repositories:
            self.__threading_call__(self._get_repository, self.repositories.values())
            self.__threading_call__(
                self._list_tags_for_resource, self.repositories.values()
            )

    def _list_repositories(self, regional_client):
        """Lists all CodeCommit repositories in the specified region.

        Retrieves all repositories using pagination and creates Repository
        objects for each repository found.

        Args:
            regional_client: AWS regional client for CodeCommit service.

        Note:
            AWS API errors are caught and logged internally; this method
            does not raise them to the caller.
        """
        logger.info("CodeCommit - Listing repositories...")
        try:
            list_repositories_paginator = regional_client.get_paginator(
                "list_repositories"
            )
            for page in list_repositories_paginator.paginate():
                for repository in page["repositories"]:
                    repository_arn = f"arn:{self.audited_partition}:codecommit:{regional_client.region}:{self.audited_account}:{repository['repositoryName']}"
                    if self.repositories is None:
                        self.repositories = {}
                    self.repositories[repository_arn] = Repository(
                        repository_id=repository["repositoryId"],
                        name=repository["repositoryName"],
                        arn=repository_arn,
                        region=regional_client.region,
                    )
        except ClientError as error:
            if error.response["Error"]["Code"] == "AccessDenied":
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                if not self.repositories:
                    self.repositories = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_repository(self, repository):
        """Retrieves repository metadata and the tip commit of the default branch.

        Args:
            repository: Repository object to retrieve metadata for.

        Note:
            AWS API errors are caught and logged internally; this method
            does not raise them to the caller.
        """
        logger.info("CodeCommit - Getting repository metadata...")
        try:
            regional_client = self.regional_clients[repository.region]
            repository_metadata = regional_client.get_repository(
                repositoryName=repository.name
            )["repositoryMetadata"]
            repository.default_branch = repository_metadata.get("defaultBranch")

            if repository.default_branch:
                try:
                    branch_info = regional_client.get_branch(
                        repositoryName=repository.name,
                        branchName=repository.default_branch,
                    )["branch"]
                    repository.default_branch_commit_id = branch_info.get("commitId")
                except ClientError as error:
                    logger.warning(
                        f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except ClientError as error:
            if error.response["Error"]["Code"] in (
                "RepositoryDoesNotExistException",
                "EncryptionKeyAccessDeniedException",
            ):
                logger.warning(
                    f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, resource):
        """Lists tags for a given resource.

        Args:
            resource: Resource object to retrieve tags for.
        """
        logger.info("CodeCommit - Listing Tags...")
        try:
            tags_response = self.regional_clients[
                resource.region
            ].list_tags_for_resource(resourceArn=resource.arn)
            resource.tags = tags_response.get("tags", {})
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.warning(
                    f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def get_repository_files_content(
        self, repository: "Repository"
    ) -> Generator[Tuple[str, bytes], None, None]:
        """Walks the repository tree for the default branch and yields file content.

        This performs the (potentially expensive) tree walk and blob download
        lazily so it is only paid for by checks that actually need file
        content, and only for repositories that have a default branch.

        Args:
            repository: Repository object to fetch files for.

        Yields:
            Tuple[str, bytes]: The absolute file path and its raw content.
        """
        if not repository.default_branch or not repository.default_branch_commit_id:
            return

        regional_client = self.regional_clients[repository.region]
        folders_to_process = ["/"]

        while folders_to_process:
            folder_path = folders_to_process.pop()
            try:
                folder = regional_client.get_folder(
                    repositoryName=repository.name,
                    commitSpecifier=repository.default_branch_commit_id,
                    folderPath=folder_path,
                )
            except ClientError as error:
                logger.error(
                    f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                continue
            except Exception as error:
                logger.error(
                    f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                continue

            for sub_folder in folder.get("subFolders", []):
                folders_to_process.append(sub_folder["absolutePath"])

            for file_info in folder.get("files", []):
                try:
                    blob = regional_client.get_blob(
                        repositoryName=repository.name,
                        blobId=file_info["blobId"],
                    )
                    yield file_info["absolutePath"], blob.get("content")
                except ClientError as error:
                    logger.error(
                        f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                except Exception as error:
                    logger.error(
                        f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )


class Repository(BaseModel):
    """Model representing an AWS CodeCommit repository.

    Attributes:
        repository_id: The repository ID.
        name: The name of the repository.
        arn: The ARN (Amazon Resource Name) of the repository.
        region: The AWS region where the repository exists.
        default_branch: The name of the repository's default branch, if any.
        default_branch_commit_id: The commit ID the default branch currently points to.
        tags: Optional dictionary of repository tags.
    """

    repository_id: str
    name: str
    arn: str
    region: str
    default_branch: Optional[str] = None
    default_branch_commit_id: Optional[str] = None
    tags: Optional[dict] = {}
