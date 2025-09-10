from prowler.providers.common.provider import Provider
from prowler.providers.mongodbatlas.services.projects.projects_service import Projects

projects_client = Projects(Provider.get_global_provider())
