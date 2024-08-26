from operator import attrgetter

from prowler.config.config import timestamp
from prowler.lib.check.models import Check
from prowler.lib.logger import logger
from prowler.lib.outputs.utils import unroll_list, unroll_tags
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
def fill_common_finding_data(finding: dict, check: Check, unix_timestamp: bool) -> dict:
    """
    Fill the common finding data for a given check finding.

    Args:
        finding: The finding dictionary.
        check: The check object.
        unix_timestamp: If the timestamp should be in Unix format.

    Returns:
        finding_data: The finding data dictionary.
    """

    finding_data = {
        "timestamp": outputs_unix_timestamp(unix_timestamp, timestamp),
        "check_id": check.CheckID,
        "check_title": check.CheckTitle,
        "check_type": ",".join(check.CheckType),
        "status": finding["status"],
        "status_extended": finding["status_extended"],
        "service_name": check.ServiceName,
        "subservice_name": check.SubServiceName,
        "severity": check.Severity,
        "resource_type": check.ResourceType,
        "resource_details": finding["resource_details"],
        "resource_tags": unroll_tags(finding["resource_tags"]),
        "description": check.Description,
        "risk": check.Risk,
        "related_url": check.RelatedUrl,
        "remediation_recommendation_text": (check.Remediation.Recommendation.Text),
        "remediation_recommendation_url": (check.Remediation.Recommendation.Url),
        "remediation_code_nativeiac": (check.Remediation.Code.NativeIaC),
        "remediation_code_terraform": (check.Remediation.Code.Terraform),
        "remediation_code_cli": (check.Remediation.Code.CLI),
        "remediation_code_other": (check.Remediation.Code.Other),
        "categories": unroll_list(check.Categories),
        "depends_on": unroll_list(check.DependsOn),
        "related_to": unroll_list(check.RelatedTo),
        "notes": check.Notes,
    }
    return finding_data
