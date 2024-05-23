from csv import DictWriter
from io import TextIOWrapper
from typing import Any

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_ocsf_file_suffix,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.common_models import FindingOutput
from prowler.lib.outputs.compliance.mitre_attack.models import (
    MitreAttackAWS,
    MitreAttackAzure,
    MitreAttackGCP,
)
from prowler.lib.outputs.compliance.models import (
    Check_Output_CSV_AWS_CIS,
    Check_Output_CSV_AWS_ISO27001_2013,
    Check_Output_CSV_AWS_Well_Architected,
    Check_Output_CSV_AZURE_CIS,
    Check_Output_CSV_ENS_RD2022,
    Check_Output_CSV_GCP_CIS,
    Check_Output_CSV_Generic_Compliance,
    Check_Output_CSV_KUBERNETES_CIS,
)
from prowler.lib.outputs.csv.csv import generate_csv_fields
from prowler.lib.outputs.html.html import add_html_header
from prowler.lib.utils.utils import file_exists, open_file


def initialize_file_descriptor(
    filename: str,
    output_mode: str,
    provider: Any = None,
    format: Any = FindingOutput,
) -> TextIOWrapper:
    """Open/Create the output file. If needed include headers or the required format, by default will use the FindingOutput"""
    try:
        if file_exists(filename):
            file_descriptor = open_file(
                filename,
                "a",
            )
        else:
            file_descriptor = open_file(
                filename,
                "a",
            )

            if output_mode in ("json-asff", "json-ocsf"):
                file_descriptor.write("[")
            elif "html" in output_mode:
                add_html_header(file_descriptor, provider)
            else:
                # Format is the class model of the CSV format to print the headers
                csv_header = [x.upper() for x in generate_csv_fields(format)]
                csv_writer = DictWriter(
                    file_descriptor, fieldnames=csv_header, delimiter=";"
                )
                csv_writer.writeheader()
        return file_descriptor
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def fill_file_descriptors(output_modes, output_directory, output_filename, provider):
    try:
        file_descriptors = {}
        if output_modes:
            for output_mode in output_modes:
                if output_mode == "csv":
                    filename = f"{output_directory}/{output_filename}{csv_file_suffix}"
                    output_model = FindingOutput
                    file_descriptor = initialize_file_descriptor(
                        filename,
                        output_mode,
                        provider.type,
                        output_model,
                    )
                    file_descriptors.update({output_mode: file_descriptor})

                elif output_mode == "html":
                    filename = f"{output_directory}/{output_filename}{html_file_suffix}"
                    file_descriptor = initialize_file_descriptor(
                        filename, output_mode, provider
                    )
                    file_descriptors.update({output_mode: file_descriptor})

                elif output_mode == "json-ocsf":
                    filename = (
                        f"{output_directory}/{output_filename}{json_ocsf_file_suffix}"
                    )
                    file_descriptor = initialize_file_descriptor(filename, output_mode)
                    file_descriptors.update({output_mode: file_descriptor})

                elif provider.type == "gcp":
                    filename = f"{output_directory}/compliance/{output_filename}_{output_mode}{csv_file_suffix}"
                    if "cis_" in output_mode:
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            provider.type,
                            Check_Output_CSV_GCP_CIS,
                        )
                        file_descriptors.update({output_mode: file_descriptor})
                    elif output_mode == "mitre_attack_gcp":
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            provider.type,
                            MitreAttackGCP,
                        )
                        file_descriptors.update({output_mode: file_descriptor})
                    else:
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            provider.type,
                            Check_Output_CSV_Generic_Compliance,
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                elif provider.type == "kubernetes":
                    filename = f"{output_directory}/compliance/{output_filename}_{output_mode}{csv_file_suffix}"
                    if "cis_" in output_mode:
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            provider.type,
                            Check_Output_CSV_KUBERNETES_CIS,
                        )
                        file_descriptors.update({output_mode: file_descriptor})
                    else:
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            provider.type,
                            Check_Output_CSV_Generic_Compliance,
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                elif provider.type == "azure":
                    filename = f"{output_directory}/compliance/{output_filename}_{output_mode}{csv_file_suffix}"
                    if "cis_" in output_mode:
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            provider.type,
                            Check_Output_CSV_AZURE_CIS,
                        )
                        file_descriptors.update({output_mode: file_descriptor})
                    elif output_mode == "mitre_attack_azure":
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            provider.type,
                            MitreAttackAzure,
                        )
                        file_descriptors.update({output_mode: file_descriptor})
                    else:
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            provider.type,
                            Check_Output_CSV_Generic_Compliance,
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                elif provider.type == "aws":
                    if output_mode == "json-asff":
                        filename = f"{output_directory}/{output_filename}{json_asff_file_suffix}"
                        file_descriptor = initialize_file_descriptor(
                            filename, output_mode
                        )
                        file_descriptors.update({output_mode: file_descriptor})
                    else:  # Compliance frameworks
                        filename = f"{output_directory}/compliance/{output_filename}_{output_mode}{csv_file_suffix}"
                        if output_mode == "ens_rd2022_aws":
                            file_descriptor = initialize_file_descriptor(
                                filename,
                                output_mode,
                                provider.type,
                                Check_Output_CSV_ENS_RD2022,
                            )
                            file_descriptors.update({output_mode: file_descriptor})

                        elif "cis_" in output_mode:
                            file_descriptor = initialize_file_descriptor(
                                filename,
                                output_mode,
                                provider.type,
                                Check_Output_CSV_AWS_CIS,
                            )
                            file_descriptors.update({output_mode: file_descriptor})

                        elif "aws_well_architected_framework" in output_mode:
                            file_descriptor = initialize_file_descriptor(
                                filename,
                                output_mode,
                                provider.type,
                                Check_Output_CSV_AWS_Well_Architected,
                            )
                            file_descriptors.update({output_mode: file_descriptor})

                        elif output_mode == "iso27001_2013_aws":
                            file_descriptor = initialize_file_descriptor(
                                filename,
                                output_mode,
                                provider.type,
                                Check_Output_CSV_AWS_ISO27001_2013,
                            )
                            file_descriptors.update({output_mode: file_descriptor})

                        elif output_mode == "mitre_attack_aws":
                            file_descriptor = initialize_file_descriptor(
                                filename,
                                output_mode,
                                provider.type,
                                MitreAttackAWS,
                            )
                            file_descriptors.update({output_mode: file_descriptor})

                        else:
                            # Generic Compliance framework
                            file_descriptor = initialize_file_descriptor(
                                filename,
                                output_mode,
                                provider.type,
                                Check_Output_CSV_Generic_Compliance,
                            )
                            file_descriptors.update({output_mode: file_descriptor})

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return file_descriptors
