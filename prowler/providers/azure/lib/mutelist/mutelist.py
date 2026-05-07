from prowler.lib.check.models import Check_Report_Azure
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class AzureMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: Check_Report_Azure,
        subscription_id: str,
        subscription_name: str = "",
    ) -> bool:
        account_names = [subscription_id]
        for account_name in (subscription_name, finding.subscription):
            if account_name and account_name not in account_names:
                account_names.append(account_name)

        tags = unroll_dict(unroll_tags(finding.resource_tags))

        for account_name in account_names:
            if self.is_muted(
                account_name,
                finding.check_metadata.CheckID,
                finding.location,
                finding.resource_name,
                tags,
            ):
                return True

        return False
