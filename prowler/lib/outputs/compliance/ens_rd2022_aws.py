from csv import DictWriter

from prowler.config.config import timestamp
from prowler.lib.outputs.csv.csv import generate_csv_fields
from prowler.lib.outputs.models import Check_Output_CSV_ENS_RD2022
from prowler.lib.utils.utils import outputs_unix_timestamp


def write_compliance_row_ens_rd2022_aws(
    file_descriptors, finding, compliance, output_options, provider
):
    compliance_output = "ens_rd2022_aws"
    csv_header = generate_csv_fields(Check_Output_CSV_ENS_RD2022)
    csv_writer = DictWriter(
        file_descriptors[compliance_output],
        fieldnames=csv_header,
        delimiter=";",
    )
    for requirement in compliance.Requirements:
        requirement_description = requirement.Description
        requirement_id = requirement.Id
        for attribute in requirement.Attributes:
            compliance_row = Check_Output_CSV_ENS_RD2022(
                Provider=finding.check_metadata.Provider,
                Description=compliance.Description,
                AccountId=provider.identity.account,
                Region=finding.region,
                AssessmentDate=outputs_unix_timestamp(
                    output_options.unix_timestamp, timestamp
                ),
                Requirements_Id=requirement_id,
                Requirements_Description=requirement_description,
                Requirements_Attributes_IdGrupoControl=attribute.IdGrupoControl,
                Requirements_Attributes_Marco=attribute.Marco,
                Requirements_Attributes_Categoria=attribute.Categoria,
                Requirements_Attributes_DescripcionControl=attribute.DescripcionControl,
                Requirements_Attributes_Nivel=attribute.Nivel,
                Requirements_Attributes_Tipo=attribute.Tipo,
                Requirements_Attributes_Dimensiones=",".join(attribute.Dimensiones),
                Status=finding.status,
                StatusExtended=finding.status_extended,
                ResourceId=finding.resource_id,
                CheckId=finding.check_metadata.CheckID,
            )

            csv_writer.writerow(compliance_row.__dict__)
