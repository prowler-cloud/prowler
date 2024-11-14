from prowler.providers.aws.services.servicecatalog.servicecatalog_service import (
    ServiceCatalog,
)
from prowler.providers.common.provider import Provider

servicecatalog_client = ServiceCatalog(Provider.get_global_provider())
