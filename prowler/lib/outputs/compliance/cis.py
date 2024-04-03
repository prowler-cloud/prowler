from prowler.lib.logger import logger
from prowler.lib.outputs.compliance.cis_aws import generate_compliance_row_cis_aws
from prowler.lib.outputs.compliance.cis_azure import generate_compliance_row_cis_azure
from prowler.lib.outputs.compliance.cis_gcp import generate_compliance_row_cis_gcp
from prowler.lib.outputs.compliance.cis_kubernetes import (
    generate_compliance_row_cis_kubernetes,
)
from prowler.lib.outputs.csv.csv import write_csv


def write_compliance_row_cis(
    file_descriptors,
    finding,
    compliance,
    output_options,
    provider,
    input_compliance_frameworks,
):
    try:
        compliance_output = (
            "cis_" + compliance.Version + "_" + compliance.Provider.lower()
        )

        # Only with the version of CIS that was selected
        if compliance_output in str(input_compliance_frameworks):
            for requirement in compliance.Requirements:
                for attribute in requirement.Attributes:
                    if compliance.Provider == "AWS":
                        (compliance_row, csv_header) = generate_compliance_row_cis_aws(
                            finding,
                            compliance,
                            requirement,
                            attribute,
                            output_options,
                            provider,
                        )
                    elif compliance.Provider == "Azure":
                        (compliance_row, csv_header) = (
                            generate_compliance_row_cis_azure(
                                finding,
                                compliance,
                                requirement,
                                attribute,
                                output_options,
                            )
                        )
                    elif compliance.Provider == "GCP":
                        (compliance_row, csv_header) = generate_compliance_row_cis_gcp(
                            finding, compliance, requirement, attribute, output_options
                        )
                    elif compliance.Provider == "Kubernetes":
                        (compliance_row, csv_header) = (
                            generate_compliance_row_cis_kubernetes(
                                finding,
                                compliance,
                                requirement,
                                attribute,
                                output_options,
                                provider,
                            )
                        )

                    write_csv(
                        file_descriptors[compliance_output], csv_header, compliance_row
                    )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
