from prowler.providers.aws.services.appstream.appstream_service import AppStream
from prowler.providers.common.provider import Provider

appstream_client = AppStream(Provider.get_global_provider())
