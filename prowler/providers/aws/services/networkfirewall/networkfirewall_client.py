from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    NetworkFirewall,
)

networkfirewall_client = NetworkFirewall(current_audit_info)
