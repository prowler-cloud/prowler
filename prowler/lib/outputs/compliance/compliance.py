import sys

from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.aws_well_architected_framework import (
    write_compliance_row_aws_well_architected_framework,
)
from prowler.lib.outputs.compliance.cis import get_cis_table, write_compliance_row_cis
from prowler.lib.outputs.compliance.ens_rd2022_aws import (
    get_ens_rd2022_aws_table,
    write_compliance_row_ens_rd2022_aws,
)
from prowler.lib.outputs.compliance.generic import (
    get_generic_compliance_table,
    write_compliance_row_generic,
)
from prowler.lib.outputs.compliance.iso27001_2013_aws import (
    write_compliance_row_iso27001_2013_aws,
)
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack import (
    get_mitre_attack_table,
    write_compliance_row_mitre_attack,
)


def add_manual_controls(
    output_options, provider, file_descriptors, input_compliance_frameworks
):
    try:
        # Check if MANUAL control was already added to output
        if "manual_check" in output_options.bulk_checks_metadata:
            manual_finding = Check_Report(
                output_options.bulk_checks_metadata["manual_check"].json()
            )
            manual_finding.status = "MANUAL"
            manual_finding.status_extended = "Manual check"
            manual_finding.resource_id = "manual_check"
            manual_finding.resource_name = "Manual check"
            manual_finding.region = ""
            manual_finding.location = ""
            manual_finding.project_id = ""
            manual_finding.subscription = ""
            manual_finding.namespace = ""
            fill_compliance(
                output_options,
                manual_finding,
                provider,
                file_descriptors,
                input_compliance_frameworks,
            )
            del output_options.bulk_checks_metadata["manual_check"]
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def get_check_compliance_frameworks_in_input(
    check_id, bulk_checks_metadata, input_compliance_frameworks
):
    """get_check_compliance_frameworks_in_input returns a list of Compliance for the given check if the compliance framework is present in the input compliance to execute"""
    check_compliances = []
    try:
        if bulk_checks_metadata and bulk_checks_metadata.get(check_id):
            for compliance in bulk_checks_metadata[check_id].Compliance:
                compliance_name = ""
                if compliance.Version:
                    compliance_name = (
                        compliance.Framework.lower()
                        + "_"
                        + compliance.Version.lower()
                        + "_"
                        + compliance.Provider.lower()
                    )
                else:
                    compliance_name = (
                        compliance.Framework.lower() + "_" + compliance.Provider.lower()
                    )
                if compliance_name.replace("-", "_") in input_compliance_frameworks:
                    check_compliances.append(compliance)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    return check_compliances


def fill_compliance(
    output_options, finding, provider, file_descriptors, input_compliance_frameworks
):
    try:
        # We have to retrieve all the check's compliance requirements and get the ones matching with the input ones
        check_compliances = get_check_compliance_frameworks_in_input(
            finding.check_metadata.CheckID,
            output_options.bulk_checks_metadata,
            input_compliance_frameworks,
        )

        for compliance in check_compliances:
            if compliance.Framework == "ENS" and compliance.Version == "RD2022":
                write_compliance_row_ens_rd2022_aws(
                    file_descriptors, finding, compliance, output_options, provider
                )

            elif compliance.Framework == "CIS":
                write_compliance_row_cis(
                    file_descriptors,
                    finding,
                    compliance,
                    output_options,
                    provider,
                    input_compliance_frameworks,
                )

            elif (
                "AWS-Well-Architected-Framework" in compliance.Framework
                and compliance.Provider == "AWS"
            ):
                write_compliance_row_aws_well_architected_framework(
                    file_descriptors, finding, compliance, output_options, provider
                )

            elif (
                compliance.Framework == "ISO27001"
                and compliance.Version == "2013"
                and compliance.Provider == "AWS"
            ):
                write_compliance_row_iso27001_2013_aws(
                    file_descriptors, finding, compliance, output_options, provider
                )

            elif compliance.Framework == "MITRE-ATTACK" and compliance.Version == "":
                write_compliance_row_mitre_attack(
                    file_descriptors, finding, compliance, provider
                )

            else:
                write_compliance_row_generic(
                    file_descriptors, finding, compliance, output_options, provider
                )

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def display_compliance_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
):
    try:
        if "ens_rd2022_aws" == compliance_framework:
            get_ens_rd2022_aws_table(
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


def get_check_compliance(finding, provider_type, output_options) -> dict:
    """get_check_compliance returns a map with the compliance framework as key and the requirements where the finding's check is present.

        Example:

    {
        "CIS-1.4": ["2.1.3"],
        "CIS-1.5": ["2.1.3"],
    }
    """
    try:
        check_compliance = {}
        # We have to retrieve all the check's compliance requirements
        if finding.check_metadata.CheckID in output_options.bulk_checks_metadata:
            for compliance in output_options.bulk_checks_metadata[
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
