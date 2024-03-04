from csv import DictWriter

from prowler.config.config import timestamp
from prowler.lib.logger import logger
from prowler.lib.outputs.models import (
    Check_Output_CSV_AWS_Well_Architected,
    generate_csv_fields,
)
from prowler.lib.utils.utils import outputs_unix_timestamp


def write_compliance_row_aws_well_architected_framework(
    file_descriptors, finding, compliance, output_options, provider
):
    try:
        compliance_output = compliance.Framework
        if compliance.Version != "":
            compliance_output += "_" + compliance.Version
        if compliance.Provider != "":
            compliance_output += "_" + compliance.Provider
        compliance_output = compliance_output.lower().replace("-", "_")
        csv_header = generate_csv_fields(Check_Output_CSV_AWS_Well_Architected)
        csv_writer = DictWriter(
            file_descriptors[compliance_output],
            fieldnames=csv_header,
            delimiter=";",
        )
        for requirement in compliance.Requirements:
            requirement_description = requirement.Description
            requirement_id = requirement.Id
            for attribute in requirement.Attributes:
                compliance_row = Check_Output_CSV_AWS_Well_Architected(
                    Provider=finding.check_metadata.Provider,
                    Description=compliance.Description,
                    AccountId=provider.identity.account,
                    Region=finding.region,
                    AssessmentDate=outputs_unix_timestamp(
                        output_options.unix_timestamp, timestamp
                    ),
                    Requirements_Id=requirement_id,
                    Requirements_Description=requirement_description,
                    Requirements_Attributes_Name=attribute.Name,
                    Requirements_Attributes_WellArchitectedQuestionId=attribute.WellArchitectedQuestionId,
                    Requirements_Attributes_WellArchitectedPracticeId=attribute.WellArchitectedPracticeId,
                    Requirements_Attributes_Section=attribute.Section,
                    Requirements_Attributes_SubSection=attribute.SubSection,
                    Requirements_Attributes_LevelOfRisk=attribute.LevelOfRisk,
                    Requirements_Attributes_AssessmentMethod=attribute.AssessmentMethod,
                    Requirements_Attributes_Description=attribute.Description,
                    Requirements_Attributes_ImplementationGuidanceUrl=attribute.ImplementationGuidanceUrl,
                    Status=finding.status,
                    StatusExtended=finding.status_extended,
                    ResourceId=finding.resource_id,
                    CheckId=finding.check_metadata.CheckID,
                )

                csv_writer.writerow(compliance_row.__dict__)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
