from prowler.providers.common.provider import Provider
from prowler.providers.vercel.services.project.project_service import Project

project_client = Project(Provider.get_global_provider())
