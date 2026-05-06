from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger


# TODO: this should be in the Check class
def get_check_compliance(
    finding: Check_Report, provider_type: str, bulk_checks_metadata: dict
) -> dict:
    """get_check_compliance returns a map with the compliance framework as key and the requirements where the finding's check is present.

        Example:

    {
        "CIS-1.4": ["2.1.3"],
        "CIS-1.5": ["2.1.3"],
    }

    Args:
        finding (Any): The Check_Report finding
        provider_type (str): The provider type
        bulk_checks_metadata (dict): The bulk checks metadata

    Returns:
        dict: The compliance framework as key and the requirements where the finding's check is present.
    """
    try:
        check_compliance = {}
        # We have to retrieve all the check's compliance requirements
        if finding.check_metadata.CheckID in bulk_checks_metadata:
            for compliance in bulk_checks_metadata[
                finding.check_metadata.CheckID
            ].Compliance:
                compliance_fw = compliance.Framework
                if compliance.Version:
                    compliance_fw = f"{compliance_fw}-{compliance.Version}"
                # compliance.Provider == "Azure" or "Kubernetes"
                # provider_type == "azure" or "kubernetes"
                if compliance.Provider.upper() == provider_type.upper():
                    if compliance_fw not in check_compliance:
                        check_compliance[compliance_fw] = []
                    for requirement in compliance.Requirements:
                        check_compliance[compliance_fw].append(requirement.Id)
        return check_compliance
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        return {}
