from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class OpennebulaMutelist(Mutelist):
    def is_finding_muted(
        self,
        # finding: Check_Report_Opennebula,
    ) -> bool:
        return False


