from operator import attrgetter

from prowler.config.config import timestamp
from prowler.lib.logger import logger
from prowler.lib.outputs.utils import unroll_tags
from prowler.lib.utils.utils import outputs_unix_timestamp


def get_provider_data_mapping(provider) -> dict:
    data = {}
    for generic_field, provider_field in provider.get_output_mapping.items():
        try:
            provider_value = attrgetter(provider_field)(provider)
            data[generic_field] = provider_value
        except AttributeError:
            data[generic_field] = ""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
    return data


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
