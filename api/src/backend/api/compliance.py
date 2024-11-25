from types import MappingProxyType

from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.models import CheckMetadata

from api.models import Provider

PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE = {}
PROWLER_CHECKS = {}


def get_prowler_provider_checks(provider_type: Provider.ProviderChoices):
    """
    Retrieve all check IDs for the specified provider type.

    This function fetches the check metadata for the given cloud provider
    and returns an iterable of check IDs.

    Args:
        provider_type (Provider.ProviderChoices): The provider type
            (e.g., 'aws', 'azure') for which to retrieve check IDs.

    Returns:
        Iterable[str]: An iterable of check IDs associated with the specified provider type.
    """
    return CheckMetadata.get_bulk(provider_type).keys()


def get_prowler_provider_compliance(provider_type: Provider.ProviderChoices) -> dict:
    """
    Retrieve the Prowler compliance data for a specified provider type.

    This function fetches the compliance frameworks and their associated
    requirements for the given cloud provider.

    Args:
        provider_type (Provider.ProviderChoices): The provider type
            (e.g., 'aws', 'azure') for which to retrieve compliance data.

    Returns:
        dict: A dictionary mapping compliance framework names to their respective
            Compliance objects for the specified provider.
    """
    return Compliance.get_bulk(provider_type)


def load_prowler_compliance():
    """
    Load and initialize the Prowler compliance data and checks for all provider types.

    This function retrieves compliance data for all supported provider types,
    generates a compliance overview template, and populates the global variables
    `PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE` and `PROWLER_CHECKS` with read-only mappings
    of the compliance templates and checks, respectively.
    """
    global PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE
    global PROWLER_CHECKS

    prowler_compliance = {
        provider_type: get_prowler_provider_compliance(provider_type)
        for provider_type in Provider.ProviderChoices.values
    }
    template = generate_compliance_overview_template(prowler_compliance)
    PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE = MappingProxyType(template)
    PROWLER_CHECKS = MappingProxyType(load_prowler_checks(prowler_compliance))


def load_prowler_checks(prowler_compliance):
    """
    Generate a mapping of checks to the compliance frameworks that include them.

    This function processes the provided compliance data and creates a dictionary
    mapping each provider type to a dictionary where each check ID maps to a set
    of compliance names that include that check.

    Args:
        prowler_compliance (dict): The compliance data for all provider types,
            as returned by `get_prowler_provider_compliance`.

    Returns:
        dict: A nested dictionary where the first-level keys are provider types,
            and the values are dictionaries mapping check IDs to sets of compliance names.
    """
    checks = {}
    for provider_type in Provider.ProviderChoices.values:
        checks[provider_type] = {
            check_id: set() for check_id in get_prowler_provider_checks(provider_type)
        }
        for compliance_name, compliance_data in prowler_compliance[
            provider_type
        ].items():
            for requirement in compliance_data.Requirements:
                for check in requirement.Checks:
                    try:
                        checks[provider_type][check].add(compliance_name)
                    except KeyError:
                        continue
    return checks


def generate_scan_compliance(
    compliance_overview, provider_type: str, check_id: str, status: str
):
    """
    Update the compliance overview with the status of a specific check.

    This function updates the compliance overview by setting the status of the given check
    within all compliance frameworks and requirements that include it. It then updates the
    requirement status to 'FAIL' if any of its checks have failed, and adjusts the counts
    of passed and failed requirements in the compliance overview.

    Args:
        compliance_overview (dict): The compliance overview data structure to update.
        provider_type (str): The provider type (e.g., 'aws', 'azure') associated with the check.
        check_id (str): The identifier of the check whose status is being updated.
        status (str): The status of the check (e.g., 'PASS', 'FAIL', 'MUTED').

    Returns:
        None: This function modifies the compliance_overview in place.
    """
    for compliance_id in PROWLER_CHECKS[provider_type][check_id]:
        for requirement in compliance_overview[compliance_id]["requirements"].values():
            if check_id in requirement["checks"]:
                requirement["checks"][check_id] = status
                requirement["checks_status"][status.lower()] += 1

            if requirement["status"] != "FAIL" and any(
                value == "FAIL" for value in requirement["checks"].values()
            ):
                requirement["status"] = "FAIL"
                compliance_overview[compliance_id]["requirements_status"]["passed"] -= 1
                compliance_overview[compliance_id]["requirements_status"]["failed"] += 1


def generate_compliance_overview_template(prowler_compliance: dict):
    """
    Generate a compliance overview template for all provider types.

    This function creates a nested dictionary structure representing the compliance
    overview template for each provider type, compliance framework, and requirement.
    It initializes the status of all checks and requirements, and calculates initial
    counts for requirements status.

    Args:
        prowler_compliance (dict): The compliance data for all provider types,
            as returned by `get_prowler_provider_compliance`.

    Returns:
        dict: A nested dictionary representing the compliance overview template,
            structured by provider type and compliance framework.
    """
    template = {}
    for provider_type in Provider.ProviderChoices.values:
        provider_compliance = template.setdefault(provider_type, {})
        compliance_data_dict = prowler_compliance[provider_type]

        for compliance_name, compliance_data in compliance_data_dict.items():
            compliance_requirements = {}
            requirements_status = {"passed": 0, "failed": 0, "manual": 0}
            total_requirements = 0

            for requirement in compliance_data.Requirements:
                total_requirements += 1
                total_checks = len(requirement.Checks)
                checks_dict = {check: None for check in requirement.Checks}

                # Build requirement dictionary
                requirement_dict = {
                    "name": requirement.Name or requirement.Id,
                    "description": requirement.Description,
                    "attributes": [
                        dict(attribute) for attribute in requirement.Attributes
                    ],
                    "checks": checks_dict,
                    "checks_status": {
                        "pass": 0,
                        "fail": 0,
                        "manual": 0,
                        "total": total_checks,
                    },
                    "status": "PASS",
                }

                # Update requirements status
                if total_checks == 0:
                    requirements_status["manual"] += 1

                # Add requirement to compliance requirements
                compliance_requirements[requirement.Id] = requirement_dict

            # Calculate pending requirements
            pending_requirements = total_requirements - requirements_status["manual"]
            requirements_status["passed"] = pending_requirements

            # Build compliance dictionary
            compliance_dict = {
                "framework": compliance_data.Framework,
                "version": compliance_data.Version,
                "provider": provider_type,
                "description": compliance_data.Description,
                "requirements": compliance_requirements,
                "requirements_status": requirements_status,
                "total_requirements": total_requirements,
            }

            # Add compliance to provider compliance
            provider_compliance[compliance_name] = compliance_dict

    return template
