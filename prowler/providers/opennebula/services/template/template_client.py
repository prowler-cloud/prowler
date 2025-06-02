from prowler.providers.opennebula.services.template.template_service import TemplateService
from prowler.providers.common.provider import Provider

template_client = TemplateService(Provider.get_global_provider())
