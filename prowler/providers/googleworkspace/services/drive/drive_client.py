from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.drive.drive_service import Drive

drive_client = Drive(Provider.get_global_provider())
