from operator import attrgetter

from prowler.config.config import timestamp
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
def fill_common_finding_data(finding: dict, unix_timestamp: bool) -> dict:
    finding_data = {
        "timestamp": outputs_unix_timestamp(unix_timestamp, timestamp),
        "check_id": finding.check_metadata.CheckID,
        "check_title": finding.check_metadata.CheckTitle,
        "check_type": ",".join(finding.check_metadata.CheckType),
        "status": finding.status,
        "status_extended": finding.status_extended,
        "muted": finding.muted,
        "service_name": finding.check_metadata.ServiceName,
        "subservice_name": finding.check_metadata.SubServiceName,
        "severity": finding.check_metadata.Severity,
        "resource_type": finding.check_metadata.ResourceType,
        "resource_details": finding.resource_details,
        "resource_tags": unroll_tags(finding.resource_tags),
        "description": finding.check_metadata.Description,
        "risk": finding.check_metadata.Risk,
        "related_url": finding.check_metadata.RelatedUrl,
        "remediation_recommendation_text": (
            finding.check_metadata.Remediation.Recommendation.Text
        ),
        "remediation_recommendation_url": (
            finding.check_metadata.Remediation.Recommendation.Url
        ),
        "remediation_code_nativeiac": (
            finding.check_metadata.Remediation.Code.NativeIaC
        ),
        "remediation_code_terraform": (
            finding.check_metadata.Remediation.Code.Terraform
        ),
        "remediation_code_cli": (finding.check_metadata.Remediation.Code.CLI),
        "remediation_code_other": (finding.check_metadata.Remediation.Code.Other),
        "categories": unroll_list(finding.check_metadata.Categories),
        "depends_on": unroll_list(finding.check_metadata.DependsOn),
        "related_to": unroll_list(finding.check_metadata.RelatedTo),
        "notes": finding.check_metadata.Notes,
    }
    return finding_data
