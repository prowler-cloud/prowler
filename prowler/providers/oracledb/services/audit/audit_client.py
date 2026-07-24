from prowler.providers.common.provider import Provider
from prowler.providers.oracledb.services.audit.audit_service import Audit

audit_client = Audit(Provider.get_global_provider())
