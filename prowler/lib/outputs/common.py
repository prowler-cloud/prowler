from enum import Enum

from prowler.config.config import timestamp
from prowler.lib.outputs.utils import unroll_tags
from prowler.lib.utils.utils import outputs_unix_timestamp


# TODO: add test for outputs_unix_timestamp
def fill_common_finding_data(finding: dict, unix_timestamp: bool) -> dict:
    finding_data = {
        "metadata": finding.check_metadata,
        "timestamp": outputs_unix_timestamp(unix_timestamp, timestamp),
        "status": finding.status,
        "status_extended": finding.status_extended,
        "muted": finding.muted,
        "resource_details": finding.resource_details,
        "resource_tags": unroll_tags(finding.resource_tags),
    }
    return finding_data


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"
    MUTED = "MUTED"
