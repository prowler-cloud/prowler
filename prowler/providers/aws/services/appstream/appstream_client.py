from prowler.providers.aws.services.appstream.appstream_service import AppStream
from prowler.providers.common.common import get_global_provider

appstream_client = AppStream(get_global_provider())
