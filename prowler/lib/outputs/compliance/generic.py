from csv import DictWriter

from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color, timestamp
from prowler.lib.outputs.compliance.models import Check_Output_CSV_Generic_Compliance
from prowler.lib.outputs.csv.csv import generate_csv_fields
from prowler.lib.utils.utils import outputs_unix_timestamp


def write_compliance_row_generic(
    file_descriptors, finding, compliance, output_options, provider
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
                AccountId=provider.identity.account,
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
                Muted=finding.muted,
            )
            csv_writer.writerow(compliance_row.__dict__)


def get_generic_compliance_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
    compliance_overview: bool,
):
    pass_count = []
    fail_count = []
    muted_count = []
    for index, finding in enumerate(findings):
        check = bulk_checks_metadata[finding.check_metadata.CheckID]
        check_compliances = check.Compliance
        for compliance in check_compliances:
            if (
                compliance.Framework.upper()
                in compliance_framework.upper().replace("_", "-")
                and compliance.Version in compliance_framework.upper()
                and compliance.Provider in compliance_framework.upper()
            ):
                for requirement in compliance.Requirements:
                    for attribute in requirement.Attributes:
                        if finding.muted:
                            if index not in muted_count:
                                muted_count.append(index)
                        else:
                            if finding.status == "FAIL" and index not in fail_count:
                                fail_count.append(index)
                            elif finding.status == "PASS" and index not in pass_count:
                                pass_count.append(index)
    if (
        len(fail_count) + len(pass_count) + len(muted_count) > 1
    ):  # If there are no resources, don't print the compliance table
        print(
            f"\nCompliance Status of {Fore.YELLOW}{compliance_framework.upper()}{Style.RESET_ALL} Framework:"
        )
        overview_table = [
            [
                f"{Fore.RED}{round(len(fail_count) / len(findings) * 100, 2)}% ({len(fail_count)}) FAIL{Style.RESET_ALL}",
                f"{Fore.GREEN}{round(len(pass_count) / len(findings) * 100, 2)}% ({len(pass_count)}) PASS{Style.RESET_ALL}",
                f"{orange_color}{round(len(muted_count) / len(findings) * 100, 2)}% ({len(muted_count)}) MUTED{Style.RESET_ALL}",
            ]
        ]
        print(tabulate(overview_table, tablefmt="rounded_grid"))
        if not compliance_overview:
            print(f"\nDetailed results of {compliance_framework.upper()} are in:")
            print(
                f" - CSV: {output_directory}/compliance/{output_filename}_{compliance_framework}.csv\n"
            )
