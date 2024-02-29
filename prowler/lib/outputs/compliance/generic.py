from csv import DictWriter

from prowler.config.config import timestamp
from prowler.lib.outputs.models import (
    Check_Output_CSV_Generic_Compliance,
    generate_csv_fields,
)
from prowler.lib.utils.utils import outputs_unix_timestamp


def write_compliance_row_generic(
    file_descriptors, finding, compliance, output_options, audit_info
):
    compliance_output = compliance.Framework
    if compliance.Version != "":
        compliance_output += "_" + compliance.Version
    if compliance.Provider != "":
        compliance_output += "_" + compliance.Provider

    compliance_output = compliance_output.lower().replace("-", "_")
    csv_header = generate_csv_fields(Check_Output_CSV_Generic_Compliance)
    csv_writer = DictWriter(
        file_descriptors[compliance_output],
        fieldnames=csv_header,
        delimiter=";",
    )
    for requirement in compliance.Requirements:
        requirement_description = requirement.Description
        requirement_id = requirement.Id
        for attribute in requirement.Attributes:
            compliance_row = Check_Output_CSV_Generic_Compliance(
                Provider=finding.check_metadata.Provider,
                Description=compliance.Description,
                AccountId=audit_info.audited_account,
                Region=finding.region,
                AssessmentDate=outputs_unix_timestamp(
                    output_options.unix_timestamp, timestamp
                ),
                Requirements_Id=requirement_id,
                Requirements_Description=requirement_description,
                Requirements_Attributes_Section=attribute.Section,
                Requirements_Attributes_SubSection=attribute.SubSection,
                Requirements_Attributes_SubGroup=attribute.SubGroup,
                Requirements_Attributes_Service=attribute.Service,
                Requirements_Attributes_Type=attribute.Type,
                Status=finding.status,
                StatusExtended=finding.status_extended,
                ResourceId=finding.resource_id,
                CheckId=finding.check_metadata.CheckID,
            )
            csv_writer.writerow(compliance_row.__dict__)
