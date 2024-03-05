import sys

from pydantic import parse_obj_as

from prowler.lib.check.compliance_models import Compliance_Base_Model
from prowler.lib.check.models import Check_Metadata_Model
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
                    # Verify if check is in the requirement
                    if check in requirement.Checks:
                        # Include the requirement into the check's framework requirements
                        compliance_requirements.append(requirement)
                        # Create the Compliance_Model
                        compliance = Compliance_Base_Model(
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

        # Add requirements of Manual Controls
        for framework in bulk_compliance_frameworks.values():
            for requirement in framework.Requirements:
                compliance_requirements = []
                # Verify if requirement is Manual
                if not requirement.Checks:
                    compliance_requirements.append(requirement)
                    # Create the Compliance_Model
                    compliance = Compliance_Base_Model(
                        Framework=framework.Framework,
                        Provider=framework.Provider,
                        Version=framework.Version,
                        Description=framework.Description,
                        Requirements=compliance_requirements,
                    )
                    # Include the compliance framework for the check
                    check_compliance.append(compliance)
            # Create metadata for Manual Control
            manual_check_metadata = {
                "Provider": framework.Provider,
                "CheckID": "manual_check",
                "CheckTitle": "Manual Check",
                "CheckType": [],
                "ServiceName": "",
                "SubServiceName": "",
                "ResourceIdTemplate": "",
                "Severity": "low",
                "ResourceType": "",
                "Description": "",
                "Risk": "",
                "RelatedUrl": "",
                "Remediation": {
                    "Code": {"CLI": "", "NativeIaC": "", "Other": "", "Terraform": ""},
                    "Recommendation": {"Text": "", "Url": ""},
                },
                "Categories": [],
                "Tags": {},
                "DependsOn": [],
                "RelatedTo": [],
                "Notes": "",
            }
            manual_check = parse_obj_as(Check_Metadata_Model, manual_check_metadata)
            # Save it into the check's metadata
            bulk_checks_metadata["manual_check"] = manual_check
            bulk_checks_metadata["manual_check"].Compliance = check_compliance

        return bulk_checks_metadata
    except Exception as e:
        logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}] -- {e}")
        sys.exit(1)
