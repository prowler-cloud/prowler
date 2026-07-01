from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.directory.directory_service import (
    Directory,
)

directory_client = Directory(Provider.get_global_provider())
