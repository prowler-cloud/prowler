import sys

from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.c5.c5 import get_c5_table
from prowler.lib.outputs.compliance.ccc.ccc import get_ccc_table
from prowler.lib.outputs.compliance.cis.cis import get_cis_table
from prowler.lib.outputs.compliance.csa.csa import get_csa_table
from prowler.lib.outputs.compliance.ens.ens import get_ens_table
from prowler.lib.outputs.compliance.generic.generic_table import (
    get_generic_compliance_table,
)
from prowler.lib.outputs.compliance.kisa_ismsp.kisa_ismsp import get_kisa_ismsp_table
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack import (
    get_mitre_attack_table,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore import (
    get_prowler_threatscore_table,
)
from prowler.lib.outputs.compliance.universal.universal_table import get_universal_table


def process_universal_compliance_frameworks(
    input_compliance_frameworks: set,
    universal_frameworks: dict,
    finding_outputs: list,
    output_directory: str,
    output_filename: str,
    provider: str,
    generated_outputs: dict,
) -> set:
    """Process universal compliance frameworks, generating CSV and OCSF outputs.

    For each framework in *input_compliance_frameworks* that exists in
    *universal_frameworks* and has an outputs.table_config, this function
    creates both a CSV (UniversalComplianceOutput) and an OCSF JSON
    (OCSFComplianceOutput) file.  OCSF is always generated regardless of
    the user's ``--output-formats`` flag.

    Returns the set of framework names that were processed so the caller
    can remove them before entering the legacy per-provider output loop.
    """
    from prowler.lib.outputs.compliance.universal.ocsf_compliance import (
        OCSFComplianceOutput,
    )
    from prowler.lib.outputs.compliance.universal.universal_output import (
        UniversalComplianceOutput,
    )

    processed = set()
    for compliance_name in input_compliance_frameworks:
        if not (
            compliance_name in universal_frameworks
            and universal_frameworks[compliance_name].outputs
            and universal_frameworks[compliance_name].outputs.table_config
        ):
            continue

        fw = universal_frameworks[compliance_name]

        # CSV output
        csv_path = (
            f"{output_directory}/compliance/" f"{output_filename}_{compliance_name}.csv"
        )
        output = UniversalComplianceOutput(
            findings=finding_outputs,
            framework=fw,
            file_path=csv_path,
            provider=provider,
        )
        generated_outputs["compliance"].append(output)
        output.batch_write_data_to_file()

        # OCSF output (always generated for universal frameworks)
        ocsf_path = (
            f"{output_directory}/compliance/"
            f"{output_filename}_{compliance_name}.ocsf.json"
        )
        ocsf_output = OCSFComplianceOutput(
            findings=finding_outputs,
            framework=fw,
            file_path=ocsf_path,
            provider=provider,
        )
        generated_outputs["compliance"].append(ocsf_output)
        ocsf_output.batch_write_data_to_file()

        processed.add(compliance_name)

    return processed


def display_compliance_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
    universal_frameworks: dict = None,
    provider: str = None,
    output_formats: list = None,
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
        universal_frameworks (dict): Optional universal ComplianceFramework objects
        provider (str): The current provider (e.g. "aws") for multi-provider filtering
        output_formats (list): The output formats to generate

    Returns:
        None
    """
    try:
        # Universal path: if the framework has TableConfig, use the universal renderer
        if universal_frameworks and compliance_framework in universal_frameworks:
            fw = universal_frameworks[compliance_framework]
            if fw.outputs and fw.outputs.table_config:
                get_universal_table(
                    findings,
                    bulk_checks_metadata,
                    compliance_framework,
                    output_filename,
                    output_directory,
                    compliance_overview,
                    framework=fw,
                    provider=provider,
                    output_formats=output_formats,
                )
                return

        if compliance_framework.startswith("cis_"):
            get_cis_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif compliance_framework.startswith("ens_"):
            get_ens_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif compliance_framework.startswith("mitre_attack"):
            get_mitre_attack_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif compliance_framework.startswith("kisa"):
            get_kisa_ismsp_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif compliance_framework.startswith("prowler_threatscore_"):
            get_prowler_threatscore_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif compliance_framework.startswith("csa_ccm_"):
            get_csa_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif compliance_framework.startswith("c5_"):
            get_c5_table(
                findings,
                bulk_checks_metadata,
                compliance_framework,
                output_filename,
                output_directory,
                compliance_overview,
            )
        elif compliance_framework.startswith("ccc_"):
            get_ccc_table(
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
