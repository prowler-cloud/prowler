from csv import DictWriter

from prowler.config.config import timestamp
from prowler.lib.outputs.models import (
    Check_Output_MITRE_ATTACK,
    generate_csv_fields,
    unroll_list,
)
from prowler.lib.utils.utils import outputs_unix_timestamp


def write_compliance_row_mitre_attack_aws(
    file_descriptors, finding, compliance, output_options, provider
):
    compliance_output = compliance.Framework
    if compliance.Version != "":
        compliance_output += "_" + compliance.Version
    if compliance.Provider != "":
        compliance_output += "_" + compliance.Provider

    compliance_output = compliance_output.lower().replace("-", "_")
    csv_header = generate_csv_fields(Check_Output_MITRE_ATTACK)
    csv_writer = DictWriter(
        file_descriptors[compliance_output],
        fieldnames=csv_header,
        delimiter=";",
    )
    for requirement in compliance.Requirements:
        requirement_description = requirement.Description
        requirement_id = requirement.Id
        requirement_name = requirement.Name
        attributes_aws_services = ""
        attributes_categories = ""
        attributes_values = ""
        attributes_comments = ""
        for attribute in requirement.Attributes:
            attributes_aws_services += attribute.AWSService + "\n"
            attributes_categories += attribute.Category + "\n"
            attributes_values += attribute.Value + "\n"
            attributes_comments += attribute.Comment + "\n"
        compliance_row = Check_Output_MITRE_ATTACK(
            Provider=finding.check_metadata.Provider,
            Description=compliance.Description,
            AccountId=provider.identity.account,
            Region=finding.region,
            AssessmentDate=outputs_unix_timestamp(
                output_options.unix_timestamp, timestamp
            ),
            Requirements_Id=requirement_id,
            Requirements_Description=requirement_description,
            Requirements_Name=requirement_name,
            Requirements_Tactics=unroll_list(requirement.Tactics),
            Requirements_SubTechniques=unroll_list(requirement.SubTechniques),
            Requirements_Platforms=unroll_list(requirement.Platforms),
            Requirements_TechniqueURL=requirement.TechniqueURL,
            Requirements_Attributes_AWSServices=attributes_aws_services,
            Requirements_Attributes_Categories=attributes_categories,
            Requirements_Attributes_Values=attributes_values,
            Requirements_Attributes_Comments=attributes_comments,
            Status=finding.status,
            StatusExtended=finding.status_extended,
            ResourceId=finding.resource_id,
            CheckId=finding.check_metadata.CheckID,
        )

        csv_writer.writerow(compliance_row.__dict__)
