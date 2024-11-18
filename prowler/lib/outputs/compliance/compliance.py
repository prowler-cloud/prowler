import sys

from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.cis.cis import get_cis_table
from prowler.lib.outputs.compliance.ens.ens import get_ens_table
from prowler.lib.outputs.compliance.generic.generic_table import (
    get_generic_compliance_table,
)
from prowler.lib.outputs.compliance.kisa_ismsp.kisa_ismsp import get_kisa_ismsp_table
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack import (
    get_mitre_attack_table,
)


def display_compliance_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
) -> None:
    """
    display_compliance_table generates the compliance table for the given compliance framework.

    Args:
        findings (list): The list of findings
        bulk_checks_metadata (dict): The bulk checks metadata
        compliance_framework (str): The compliance framework to generate the table
        output_filename (str): The output filename
        output_directory (str): The output directory
        compliance_overview (bool): The compliance

    Returns:
        None
    """
    try:
        if "ens_" in compliance_framework:
            get_ens_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif "cis_" in compliance_framework:
            get_cis_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif "mitre_attack" in compliance_framework:
            get_mitre_attack_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif "kisa_isms_" in compliance_framework:
            get_kisa_ismsp_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        else:
            get_generic_compliance_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
        )
        sys.exit(1)


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
