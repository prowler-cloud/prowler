import sys

from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.c5.c5 import get_c5_table
from prowler.lib.outputs.compliance.ccc.ccc import get_ccc_table
from prowler.lib.outputs.compliance.cis.cis import get_cis_table
from prowler.lib.outputs.compliance.compliance_check import (  # noqa: F401 - re-export for backward compatibility
    get_check_compliance,
)
from prowler.lib.outputs.compliance.csa.csa import get_csa_table
from prowler.lib.outputs.compliance.ens.ens import get_ens_table
from prowler.lib.outputs.compliance.essential_eight.essential_eight import (
    get_essential_eight_table,
)
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

    The function is idempotent: it tracks already-created writers via
    ``generated_outputs["compliance"]`` keyed by ``file_path``. If invoked
    again for the same framework (e.g. once per streaming batch), it
    reuses the existing writer instead of recreating it. This guarantees
    one output writer per framework for the whole execution and keeps
    the OCSF JSON array valid across multiple calls.

    Returns the set of framework names that were processed so the caller
    can remove them before entering the legacy per-provider output loop.
    """
    from prowler.lib.outputs.compliance.universal.ocsf_compliance import (
        OCSFComplianceOutput,
    )
    from prowler.lib.outputs.compliance.universal.universal_output import (
        UniversalComplianceOutput,
    )

    existing_writers = {
        getattr(out, "file_path", None): out
        for out in generated_outputs.get("compliance", [])
        if isinstance(out, (UniversalComplianceOutput, OCSFComplianceOutput))
    }

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
        if csv_path not in existing_writers:
            output = UniversalComplianceOutput(
                findings=finding_outputs,
                framework=fw,
                file_path=csv_path,
                provider=provider,
            )
            generated_outputs["compliance"].append(output)
            existing_writers[csv_path] = output
            output.batch_write_data_to_file()

        # OCSF output (always generated for universal frameworks)
        ocsf_path = (
            f"{output_directory}/compliance/"
            f"{output_filename}_{compliance_name}.ocsf.json"
        )
        if ocsf_path not in existing_writers:
            ocsf_output = OCSFComplianceOutput(
                findings=finding_outputs,
                framework=fw,
                file_path=ocsf_path,
                provider=provider,
            )
            generated_outputs["compliance"].append(ocsf_output)
            existing_writers[ocsf_path] = ocsf_output
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
    # Filter out findings with dynamic CheckIDs not present in bulk_checks_metadata
    findings = [f for f in findings if f.check_metadata.CheckID in bulk_checks_metadata]

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
        elif "essential_eight" in compliance_framework:
            get_essential_eight_table(
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
