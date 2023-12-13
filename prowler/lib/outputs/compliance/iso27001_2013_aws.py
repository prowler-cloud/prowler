from csv import DictWriter

from prowler.config.config import timestamp
from prowler.lib.outputs.models import (
    Check_Output_CSV_AWS_ISO27001_2013,
    generate_csv_fields,
)
from prowler.lib.utils.utils import outputs_unix_timestamp


def write_compliance_row_iso27001_2013_aws(
    file_descriptors, finding, compliance, output_options, audit_info
):
    compliance_output = compliance.Framework
    if compliance.Version != "":
        compliance_output += "_" + compliance.Version
    if compliance.Provider != "":
        compliance_output += "_" + compliance.Provider

    compliance_output = compliance_output.lower().replace("-", "_")
    csv_header = generate_csv_fields(Check_Output_CSV_AWS_ISO27001_2013)
    csv_writer = DictWriter(
        file_descriptors[compliance_output],
        fieldnames=csv_header,
        delimiter=";",
    )
    for requirement in compliance.Requirements:
        requirement_description = requirement.Description
        requirement_id = requirement.Id
        requirement_name = requirement.Name
        for attribute in requirement.Attributes:
            compliance_row = Check_Output_CSV_AWS_ISO27001_2013(
                Provider=finding.check_metadata.Provider,
                Description=compliance.Description,
                AccountId=audit_info.audited_account,
                Region=finding.region,
                AssessmentDate=outputs_unix_timestamp(
                    output_options.unix_timestamp, timestamp
                ),
                Requirements_Id=requirement_id,
                Requirements_Name=requirement_name,
                Requirements_Description=requirement_description,
                Requirements_Attributes_Category=attribute.Category,
                Requirements_Attributes_Objetive_ID=attribute.Objetive_ID,
                Requirements_Attributes_Objetive_Name=attribute.Objetive_Name,
                Requirements_Attributes_Check_Summary=attribute.Check_Summary,
                Status=finding.status,
                StatusExtended=finding.status_extended,
                ResourceId=finding.resource_id,
                CheckId=finding.check_metadata.CheckID,
            )

            csv_writer.writerow(compliance_row.__dict__)
