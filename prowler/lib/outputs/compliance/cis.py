from prowler.lib.outputs.compliance.cis_aws import generate_compliance_row_cis_aws
from prowler.lib.outputs.compliance.cis_gcp import generate_compliance_row_cis_gcp
from prowler.lib.outputs.csv import write_csv


def write_compliance_row_cis(
    file_descriptors,
    finding,
    compliance,
    output_options,
    audit_info,
    input_compliance_frameworks,
):
    compliance_output = "cis_" + compliance.Version + "_" + compliance.Provider.lower()

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
                        audit_info,
                    )
                elif compliance.Provider == "GCP":
                    (compliance_row, csv_header) = generate_compliance_row_cis_gcp(
                        finding, compliance, output_options
                    )

                write_csv(
                    file_descriptors[compliance_output], csv_header, compliance_row
                )
