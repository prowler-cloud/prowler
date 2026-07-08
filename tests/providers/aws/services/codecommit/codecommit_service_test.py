from unittest.mock import MagicMock, patch

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.services.codecommit.codecommit_service import (
    CodeCommit,
    Repository,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

repository_name = "test-repo"
repository_id = "repo-id-1234"
repository_arn = f"arn:{AWS_COMMERCIAL_PARTITION}:codecommit:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{repository_name}"
default_branch = "main"
commit_id = "commit-1234"

# Mocking API calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListRepositories":
        return {
            "repositories": [
                {"repositoryName": repository_name, "repositoryId": repository_id}
            ]
        }
    elif operation_name == "GetRepository":
        return {
            "repositoryMetadata": {
                "repositoryId": repository_id,
                "repositoryName": repository_name,
                "defaultBranch": default_branch,
            }
        }
    elif operation_name == "GetBranch":
        return {"branch": {"branchName": default_branch, "commitId": commit_id}}
    elif operation_name == "ListTagsForResource":
        return {"tags": {"Environment": "Test"}}
    elif operation_name == "GetFolder":
        if kwarg["folderPath"] == "/":
            return {
                "commitId": commit_id,
                "folderPath": "/",
                "subFolders": [{"absolutePath": "/src"}],
                "files": [{"absolutePath": "README.md", "blobId": "blob-readme"}],
            }
        elif kwarg["folderPath"] == "/src":
            return {
                "commitId": commit_id,
                "folderPath": "/src",
                "subFolders": [],
                "files": [
                    {"absolutePath": "/src/secrets.py", "blobId": "blob-secrets"}
                ],
            }
    elif operation_name == "GetBlob":
        if kwarg["blobId"] == "blob-readme":
            return {"content": b"# Test repository\n"}
        elif kwarg["blobId"] == "blob-secrets":
            return {"content": b'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'}
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


def mock_make_api_call_list_repositories_access_denied(self, operation_name, kwarg):
    if operation_name == "ListRepositories":
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_list_repositories_client_error(self, operation_name, kwarg):
    if operation_name == "ListRepositories":
        raise ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_repository_errors(self, operation_name, kwarg):
    if operation_name == "ListRepositories":
        return {
            "repositories": [
                {"repositoryName": repository_name, "repositoryId": repository_id},
                {"repositoryName": "repo-not-exist", "repositoryId": "repo-id-2"},
                {"repositoryName": "repo-other-error", "repositoryId": "repo-id-3"},
                {"repositoryName": "repo-branch-error", "repositoryId": "repo-id-4"},
            ]
        }
    elif operation_name == "GetRepository":
        name = kwarg["repositoryName"]
        if name == "repo-not-exist":
            raise ClientError(
                {
                    "Error": {
                        "Code": "RepositoryDoesNotExistException",
                        "Message": "Repository does not exist",
                    }
                },
                operation_name,
            )
        if name == "repo-other-error":
            raise ClientError(
                {"Error": {"Code": "InternalServerException", "Message": "Boom"}},
                operation_name,
            )
        return {
            "repositoryMetadata": {
                "repositoryId": name,
                "repositoryName": name,
                "defaultBranch": default_branch,
            }
        }
    elif operation_name == "GetBranch":
        if kwarg["repositoryName"] == "repo-branch-error":
            raise ClientError(
                {"Error": {"Code": "InternalServerException", "Message": "Boom"}},
                operation_name,
            )
        return {"branch": {"branchName": default_branch, "commitId": commit_id}}
    elif operation_name == "ListTagsForResource":
        return {"tags": {}}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_tags_errors(self, operation_name, kwarg):
    if operation_name == "ListRepositories":
        return {
            "repositories": [
                {"repositoryName": "tags-not-found", "repositoryId": "repo-id-1"},
                {"repositoryName": "tags-other-error", "repositoryId": "repo-id-2"},
            ]
        }
    elif operation_name == "GetRepository":
        name = kwarg["repositoryName"]
        return {
            "repositoryMetadata": {
                "repositoryId": name,
                "repositoryName": name,
                "defaultBranch": default_branch,
            }
        }
    elif operation_name == "GetBranch":
        return {"branch": {"branchName": default_branch, "commitId": commit_id}}
    elif operation_name == "ListTagsForResource":
        if "tags-not-found" in kwarg["resourceArn"]:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "Not found",
                    }
                },
                operation_name,
            )
        if "tags-other-error" in kwarg["resourceArn"]:
            raise ClientError(
                {"Error": {"Code": "InternalServerException", "Message": "Boom"}},
                operation_name,
            )
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_files_errors(self, operation_name, kwarg):
    if operation_name == "ListRepositories":
        return {
            "repositories": [
                {"repositoryName": repository_name, "repositoryId": repository_id}
            ]
        }
    elif operation_name == "GetRepository":
        return {
            "repositoryMetadata": {
                "repositoryId": repository_id,
                "repositoryName": repository_name,
                "defaultBranch": default_branch,
            }
        }
    elif operation_name == "GetBranch":
        return {"branch": {"branchName": default_branch, "commitId": commit_id}}
    elif operation_name == "ListTagsForResource":
        return {"tags": {}}
    elif operation_name == "GetFolder":
        if kwarg["folderPath"] == "/":
            return {
                "commitId": commit_id,
                "folderPath": "/",
                "subFolders": [
                    {"absolutePath": "/broken-folder"},
                    {"absolutePath": "/broken-folder-2"},
                    {"absolutePath": "/src"},
                ],
                "files": [
                    {"absolutePath": "README.md", "blobId": "blob-readme"},
                    {"absolutePath": "bad-blob.txt", "blobId": "blob-bad"},
                    {"absolutePath": "error-blob.txt", "blobId": "blob-error"},
                ],
            }
        elif kwarg["folderPath"] == "/broken-folder":
            raise ClientError(
                {
                    "Error": {
                        "Code": "EncryptionKeyAccessDeniedException",
                        "Message": "Access denied",
                    }
                },
                operation_name,
            )
        elif kwarg["folderPath"] == "/broken-folder-2":
            raise Exception("Generic folder error")
        elif kwarg["folderPath"] == "/src":
            return {
                "commitId": commit_id,
                "folderPath": "/src",
                "subFolders": [],
                "files": [
                    {"absolutePath": "/src/secrets.py", "blobId": "blob-secrets"}
                ],
            }
    elif operation_name == "GetBlob":
        if kwarg["blobId"] == "blob-readme":
            return {"content": b"# Test repository\n"}
        elif kwarg["blobId"] == "blob-secrets":
            return {"content": b'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'}
        elif kwarg["blobId"] == "blob-bad":
            raise ClientError(
                {
                    "Error": {
                        "Code": "BlobIdDoesNotExistException",
                        "Message": "Blob not found",
                    }
                },
                operation_name,
            )
        elif kwarg["blobId"] == "blob-error":
            raise Exception("Generic blob error")
    return make_api_call(self, operation_name, kwarg)


class Test_CodeCommit_Service:
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_codecommit_service(self):
        codecommit = CodeCommit(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))

        assert codecommit.session.__class__.__name__ == "Session"
        assert codecommit.service == "codecommit"

        # Test repository properties
        assert len(codecommit.repositories) == 1
        assert isinstance(codecommit.repositories, dict)
        assert isinstance(codecommit.repositories[repository_arn], Repository)

        repository = codecommit.repositories[repository_arn]
        assert repository.repository_id == repository_id
        assert repository.name == repository_name
        assert repository.arn == repository_arn
        assert repository.region == AWS_REGION_EU_WEST_1
        assert repository.default_branch == default_branch
        assert repository.default_branch_commit_id == commit_id

        # Test tags
        assert repository.tags == {"Environment": "Test"}

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_get_repository_files_content(self):
        codecommit = CodeCommit(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        repository = codecommit.repositories[repository_arn]

        files = dict(codecommit.get_repository_files_content(repository))

        assert files == {
            "README.md": b"# Test repository\n",
            "/src/secrets.py": b'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
        }

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_get_repository_files_content_no_default_branch(self):
        codecommit = CodeCommit(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        repository = Repository(
            repository_id="empty-repo-id",
            name="empty-repo",
            arn=f"arn:{AWS_COMMERCIAL_PARTITION}:codecommit:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:empty-repo",
            region=AWS_REGION_EU_WEST_1,
        )

        files = list(codecommit.get_repository_files_content(repository))

        assert files == []

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_list_repositories_access_denied,
    )
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_list_repositories_access_denied_sets_none(self):
        """An AccessDenied error with no repositories collected yet sets repositories to None."""
        codecommit = CodeCommit(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))

        assert codecommit.repositories is None

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_list_repositories_client_error,
    )
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_list_repositories_other_client_error(self):
        """A non-AccessDenied ClientError is logged but does not set repositories to None."""
        codecommit = CodeCommit(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))

        assert codecommit.repositories == {}

    def test_list_repositories_generic_exception(self):
        """A non-ClientError exception while listing repositories is caught and logged."""
        codecommit = CodeCommit.__new__(CodeCommit)
        codecommit.repositories = {}
        codecommit.audited_partition = AWS_COMMERCIAL_PARTITION
        codecommit.audited_account = AWS_ACCOUNT_NUMBER

        regional_client = MagicMock()
        regional_client.region = AWS_REGION_EU_WEST_1
        regional_client.get_paginator.side_effect = Exception("Generic error")

        codecommit._list_repositories(regional_client)

        assert codecommit.repositories == {}

    def test_list_repositories_reinitializes_after_none(self):
        """A region that succeeds after another region hit AccessDenied (leaving
        repositories as None) reinitializes it to a dict instead of crashing."""
        codecommit = CodeCommit.__new__(CodeCommit)
        codecommit.repositories = None
        codecommit.audited_partition = AWS_COMMERCIAL_PARTITION
        codecommit.audited_account = AWS_ACCOUNT_NUMBER

        regional_client = MagicMock()
        regional_client.region = AWS_REGION_EU_WEST_1
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "repositories": [
                    {"repositoryName": repository_name, "repositoryId": repository_id}
                ]
            }
        ]
        regional_client.get_paginator.return_value = paginator

        codecommit._list_repositories(regional_client)

        assert isinstance(codecommit.repositories, dict)
        assert codecommit.repositories[repository_arn].name == repository_name

    def test_list_repositories_access_denied_keeps_existing_repositories(self):
        """An AccessDenied error hit after repositories were already collected
        (e.g. in another region) does not wipe out the ones already found."""
        codecommit = CodeCommit.__new__(CodeCommit)
        codecommit.repositories = {}
        codecommit.audited_partition = AWS_COMMERCIAL_PARTITION
        codecommit.audited_account = AWS_ACCOUNT_NUMBER

        healthy_client = MagicMock()
        healthy_client.region = AWS_REGION_EU_WEST_1
        healthy_paginator = MagicMock()
        healthy_paginator.paginate.return_value = [
            {
                "repositories": [
                    {"repositoryName": repository_name, "repositoryId": repository_id}
                ]
            }
        ]
        healthy_client.get_paginator.return_value = healthy_paginator

        codecommit._list_repositories(healthy_client)
        assert repository_arn in codecommit.repositories

        failing_client = MagicMock()
        failing_client.region = "us-east-1"
        failing_paginator = MagicMock()
        failing_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "ListRepositories",
        )
        failing_client.get_paginator.return_value = failing_paginator

        codecommit._list_repositories(failing_client)

        assert codecommit.repositories is not None
        assert repository_arn in codecommit.repositories

    def test_get_repository_no_default_branch(self):
        """A repository with no default branch (e.g. a brand-new empty repo)
        is left without one, and GetBranch is never called."""
        codecommit = CodeCommit.__new__(CodeCommit)
        regional_client = MagicMock()
        regional_client.get_repository.return_value = {
            "repositoryMetadata": {
                "repositoryId": repository_id,
                "repositoryName": repository_name,
            }
        }
        codecommit.regional_clients = {AWS_REGION_EU_WEST_1: regional_client}

        repository = Repository(
            repository_id=repository_id,
            name=repository_name,
            arn=repository_arn,
            region=AWS_REGION_EU_WEST_1,
        )

        codecommit._get_repository(repository)

        assert repository.default_branch is None
        assert repository.default_branch_commit_id is None
        regional_client.get_branch.assert_not_called()

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_repository_errors,
    )
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_get_repository_error_branches(self):
        """GetRepository/GetBranch errors are caught per-repository without affecting others."""
        codecommit = CodeCommit(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))

        assert len(codecommit.repositories) == 4

        def arn_for(name):
            return f"arn:{AWS_COMMERCIAL_PARTITION}:codecommit:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{name}"

        not_exist = codecommit.repositories[arn_for("repo-not-exist")]
        assert not_exist.default_branch is None
        assert not_exist.default_branch_commit_id is None

        other_error = codecommit.repositories[arn_for("repo-other-error")]
        assert other_error.default_branch is None
        assert other_error.default_branch_commit_id is None

        branch_error = codecommit.repositories[arn_for("repo-branch-error")]
        assert branch_error.default_branch == default_branch
        assert branch_error.default_branch_commit_id is None

        healthy = codecommit.repositories[arn_for(repository_name)]
        assert healthy.default_branch == default_branch
        assert healthy.default_branch_commit_id == commit_id

    def test_get_repository_generic_exception(self):
        """A non-ClientError exception while getting repository metadata is caught and logged."""
        codecommit = CodeCommit.__new__(CodeCommit)
        codecommit.regional_clients = {AWS_REGION_EU_WEST_1: MagicMock()}
        codecommit.regional_clients[AWS_REGION_EU_WEST_1].get_repository.side_effect = (
            Exception("Generic error")
        )

        repository = Repository(
            repository_id=repository_id,
            name=repository_name,
            arn=repository_arn,
            region=AWS_REGION_EU_WEST_1,
        )

        codecommit._get_repository(repository)

        assert repository.default_branch is None

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_tags_errors,
    )
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_list_tags_for_resource_error_branches(self):
        """ListTagsForResource errors are caught per-repository and tags stay empty."""
        codecommit = CodeCommit(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))

        assert len(codecommit.repositories) == 2
        for repository in codecommit.repositories.values():
            assert repository.tags == {}

    def test_list_tags_for_resource_generic_exception(self):
        """A non-ClientError exception while listing tags is caught and logged."""
        codecommit = CodeCommit.__new__(CodeCommit)
        codecommit.regional_clients = {AWS_REGION_EU_WEST_1: MagicMock()}
        codecommit.regional_clients[
            AWS_REGION_EU_WEST_1
        ].list_tags_for_resource.side_effect = Exception("Generic error")

        repository = Repository(
            repository_id=repository_id,
            name=repository_name,
            arn=repository_arn,
            region=AWS_REGION_EU_WEST_1,
        )

        codecommit._list_tags_for_resource(repository)

        assert repository.tags == {}

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_files_errors,
    )
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    @mock_aws
    def test_get_repository_files_content_handles_errors(self):
        """Broken folders and blobs are skipped without crashing the tree walk."""
        codecommit = CodeCommit(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        repository = codecommit.repositories[repository_arn]

        files = dict(codecommit.get_repository_files_content(repository))

        assert files == {
            "README.md": b"# Test repository\n",
            "/src/secrets.py": b'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
        }
