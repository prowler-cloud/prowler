from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.services.calendar.calendar_service import (
    Calendar,
)

calendar_client = Calendar(Provider.get_global_provider())
