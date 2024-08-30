import sys

from prowler.lib.check.compliance_models import Compliance
from prowler.lib.logger import logger


def update_checks_metadata_with_compliance(
    bulk_compliance_frameworks: dict, bulk_checks_metadata: dict
) -> dict:
    """
    Update the check metadata model with the compliance framework
    Args:
        bulk_compliance_frameworks (dict): The compliance frameworks
        bulk_checks_metadata (dict): The checks metadata

    Returns:
        dict: The checks metadata with the compliance frameworks
    """
    try:
        for check in bulk_checks_metadata:
            check_compliance = []
            for framework in bulk_compliance_frameworks.values():
                for requirement in framework.Requirements:
                    compliance_requirements = []
                    # Verify if check is in the requirement
                    if check in requirement.Checks:
                        # Include the requirement into the check's framework requirements
                        compliance_requirements.append(requirement)
                        # Create the Compliance
                        compliance = Compliance(
                            Framework=framework.Framework,
                            Provider=framework.Provider,
                            Version=framework.Version,
                            Description=framework.Description,
                            Requirements=compliance_requirements,
                        )
                        # Include the compliance framework for the check
                        check_compliance.append(compliance)
            # Save it into the check's metadata
            bulk_checks_metadata[check].Compliance = check_compliance
        return bulk_checks_metadata
    except Exception as e:
        logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")
        sys.exit(1)
