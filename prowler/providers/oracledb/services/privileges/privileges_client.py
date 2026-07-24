from prowler.providers.common.provider import Provider
from prowler.providers.oracledb.services.privileges.privileges_service import (
    Privileges,
)

privileges_client = Privileges(Provider.get_global_provider())
