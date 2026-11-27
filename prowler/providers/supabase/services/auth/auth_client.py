from prowler.providers.common.provider import Provider
from prowler.providers.supabase.services.auth.auth_service import Auth

auth_client = Auth(Provider.get_global_provider())
