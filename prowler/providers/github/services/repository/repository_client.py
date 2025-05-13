from prowler.providers.common.provider import Provider
from prowler.providers.github.services.repository.repository_service import Repository

repository_client = Repository(Provider.get_global_provider())
