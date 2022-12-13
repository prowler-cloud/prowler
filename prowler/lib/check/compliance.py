import sys

from prowler.lib.check.compliance_models import (
    Compliance_Base_Model,
    Compliance_Requirement,
)
from prowler.lib.logger import logger


def update_checks_metadata_with_compliance(
    bulk_compliance_frameworks: dict, bulk_checks_metadata: dict
):
    """Update the check metadata model with the compliance framework"""
    try:
        for check in bulk_checks_metadata:
            check_compliance = []
            for framework in bulk_compliance_frameworks.values():
                for requirement in framework.Requirements:
                    compliance_requirements = []
                    if check in requirement.Checks:
                        # Create the Compliance_Requirement
                        requirement = Compliance_Requirement(
                            Id=requirement.Id,
                            Description=requirement.Description,
                            Attributes=requirement.Attributes,
                            Checks=requirement.Checks,
                        )
                        # For the check metadata we don't need the "Checks" key
                        delattr(requirement, "Checks")
                        # Include the requirment into the check's framework requirements
                        compliance_requirements.append(requirement)
                        # Create the Compliance_Model
                        compliance = Compliance_Base_Model(
                            Framework=framework.Framework,
                            Provider=framework.Provider,
                            Version=framework.Version,
                            Requirements=compliance_requirements,
                        )
                        # Include the compliance framework for the check
                        check_compliance.append(compliance)
            # Save it into the check's metadata
            bulk_checks_metadata[check].Compliance = check_compliance
        return bulk_checks_metadata
    except Exception as e:
        logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")
        sys.exit()
