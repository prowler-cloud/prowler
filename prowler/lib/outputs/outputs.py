import json
import os
import sys
from csv import DictWriter
from io import TextIOWrapper
from typing import Any

from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    html_logo_img,
    html_logo_url,
    json_asff_file_suffix,
    json_file_suffix,
    orange_color,
    prowler_version,
    timestamp,
    timestamp_utc,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.models import (
    Check_Output_CSV_CIS,
    Check_Output_CSV_ENS_RD2022,
    Check_Output_JSON_ASFF,
    Compliance,
    ProductFields,
    Resource,
    Severity,
)
from prowler.lib.utils.utils import file_exists, hash_sha512, open_file
from prowler.providers.aws.lib.allowlist.allowlist import is_allowlisted
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.azure.lib.audit_info.models import Azure_Audit_Info
from prowler.providers.aws.lib.security_hub.security_hub import send_to_security_hub
from prowler.providers.common.outputs import Provider_Output_Options
from prowler.lib.outputs.models import (
    generate_provider_output_csv,
    generate_provider_output_json,
    generate_csv_fields,
    Aws_Check_Output_CSV,
    Azure_Check_Output_CSV,
)


def stdout_report(finding, color, verbose, is_quiet):
    if finding.check_metadata.Provider == "aws":
        details = finding.region
    if finding.check_metadata.Provider == "azure":
        details = finding.check_metadata.ServiceName

    if is_quiet and "FAIL" in finding.status:
        print(
            f"\t{color}{finding.status}{Style.RESET_ALL} {details}: {finding.status_extended}"
        )
    elif not is_quiet and verbose:
        print(
            f"\t{color}{finding.status}{Style.RESET_ALL} {details}: {finding.status_extended}"
        )


def report(check_findings, output_options, audit_info):
    try:
        # TO-DO Generic Function
        if isinstance(audit_info, AWS_Audit_Info):
            check_findings.sort(key=lambda x: x.region)

        if isinstance(audit_info, Azure_Audit_Info):
            check_findings.sort(key=lambda x: x.subscription)

        # Generate the required output files
        file_descriptors = {}
        if output_options.output_modes:
            # if isinstance(audit_info, AWS_Audit_Info):
            # We have to create the required output files
            file_descriptors = fill_file_descriptors(
                output_options.output_modes,
                output_options.output_directory,
                output_options.output_filename,
                audit_info,
            )

        if check_findings:
            for finding in check_findings:
                # Check if finding is allowlisted
                if output_options.allowlist_file:
                    if is_allowlisted(
                        output_options.allowlist_file,
                        audit_info.audited_account,
                        finding.check_metadata.CheckID,
                        finding.region,
                        finding.resource_id,
                    ):
                        finding.status = "WARNING"
                # Print findings by stdout
                color = set_report_color(finding.status)
                stdout_report(
                    finding, color, output_options.verbose, output_options.is_quiet
                )

                if file_descriptors:
                    # AWS specific outputs
                    if finding.check_metadata.Provider == "aws":
                        if "ens_rd2022_aws" in output_options.output_modes:
                            # We have to retrieve all the check's compliance requirements
                            check_compliance = output_options.bulk_checks_metadata[
                                finding.check_metadata.CheckID
                            ].Compliance
                            for compliance in check_compliance:
                                if (
                                    compliance.Framework == "ENS"
                                    and compliance.Version == "RD2022"
                                ):
                                    for requirement in compliance.Requirements:
                                        requirement_description = (
                                            requirement.Description
                                        )
                                        requirement_id = requirement.Id
                                        for attribute in requirement.Attributes:
                                            compliance_row = Check_Output_CSV_ENS_RD2022(
                                                Provider=finding.check_metadata.Provider,
                                                AccountId=audit_info.audited_account,
                                                Region=finding.region,
                                                AssessmentDate=timestamp.isoformat(),
                                                Requirements_Id=requirement_id,
                                                Requirements_Description=requirement_description,
                                                Requirements_Attributes_IdGrupoControl=attribute.get(
                                                    "IdGrupoControl"
                                                ),
                                                Requirements_Attributes_Marco=attribute.get(
                                                    "Marco"
                                                ),
                                                Requirements_Attributes_Categoria=attribute.get(
                                                    "Categoria"
                                                ),
                                                Requirements_Attributes_DescripcionControl=attribute.get(
                                                    "DescripcionControl"
                                                ),
                                                Requirements_Attributes_Nivel=attribute.get(
                                                    "Nivel"
                                                ),
                                                Requirements_Attributes_Tipo=attribute.get(
                                                    "Tipo"
                                                ),
                                                Requirements_Attributes_Dimensiones=",".join(
                                                    attribute.get("Dimensiones")
                                                ),
                                                Status=finding.status,
                                                StatusExtended=finding.status_extended,
                                                ResourceId=finding.resource_id,
                                                CheckId=finding.check_metadata.CheckID,
                                            )

                                    csv_header = generate_csv_fields(
                                        Check_Output_CSV_ENS_RD2022
                                    )
                                    csv_writer = DictWriter(
                                        file_descriptors["ens_rd2022_aws"],
                                        fieldnames=csv_header,
                                        delimiter=";",
                                    )
                                    csv_writer.writerow(compliance_row.__dict__)
                        elif "cis" in str(output_options.output_modes):
                            # We have to retrieve all the check's compliance requirements
                            check_compliance = output_options.bulk_checks_metadata[
                                finding.check_metadata.CheckID
                            ].Compliance
                            for compliance in check_compliance:
                                if compliance.Framework == "CIS-AWS":
                                    for requirement in compliance.Requirements:
                                        requirement_description = (
                                            requirement.Description
                                        )
                                        requirement_id = requirement.Id
                                        for attribute in requirement.Attributes:
                                            compliance_row = Check_Output_CSV_CIS(
                                                Provider=finding.check_metadata.Provider,
                                                AccountId=audit_info.audited_account,
                                                Region=finding.region,
                                                AssessmentDate=timestamp.isoformat(),
                                                Requirements_Id=requirement_id,
                                                Requirements_Description=requirement_description,
                                                Requirements_Attributes_Section=attribute.get(
                                                    "Section"
                                                ),
                                                Requirements_Attributes_Profile=attribute.get(
                                                    "Profile"
                                                ),
                                                Requirements_Attributes_AssessmentStatus=attribute.get(
                                                    "AssessmentStatus"
                                                ),
                                                Requirements_Attributes_Description=attribute.get(
                                                    "Description"
                                                ),
                                                Requirements_Attributes_RationaleStatement=attribute.get(
                                                    "RationaleStatement"
                                                ),
                                                Requirements_Attributes_ImpactStatement=attribute.get(
                                                    "ImpactStatement"
                                                ),
                                                Requirements_Attributes_RemediationProcedure=attribute.get(
                                                    "RemediationProcedure"
                                                ),
                                                Requirements_Attributes_AuditProcedure=attribute.get(
                                                    "AuditProcedure"
                                                ),
                                                Requirements_Attributes_AdditionalInformation=attribute.get(
                                                    "AdditionalInformation"
                                                ),
                                                Requirements_Attributes_References=attribute.get(
                                                    "References"
                                                ),
                                                Status=finding.status,
                                                StatusExtended=finding.status_extended,
                                                ResourceId=finding.resource_id,
                                                CheckId=finding.check_metadata.CheckID,
                                            )

                                    csv_header = generate_csv_fields(
                                        Check_Output_CSV_CIS
                                    )
                                    csv_writer = DictWriter(
                                        file_descriptors[
                                            output_options.output_modes[-1]
                                        ],
                                        fieldnames=csv_header,
                                        delimiter=";",
                                    )
                                    csv_writer.writerow(compliance_row.__dict__)

                        if "html" in file_descriptors:
                            fill_html(file_descriptors["html"], audit_info, finding)

                        file_descriptors["html"].write("")

                        if "json-asff" in file_descriptors:
                            finding_output = Check_Output_JSON_ASFF()
                            fill_json_asff(finding_output, audit_info, finding)

                            json.dump(
                                finding_output.dict(),
                                file_descriptors["json-asff"],
                                indent=4,
                            )
                            file_descriptors["json-asff"].write(",")

                        # Check if it is needed to send findings to security hub
                        if output_options.security_hub_enabled:
                            send_to_security_hub(
                                finding.region, finding_output, audit_info.audit_session
                            )

                    # Common outputs
                    if "csv" in file_descriptors:
                        csv_writer, finding_output = generate_provider_output_csv(
                            finding.check_metadata.Provider,
                            finding,
                            audit_info,
                            "csv",
                            file_descriptors["csv"],
                        )
                        csv_writer.writerow(finding_output.__dict__)

                    if "json" in file_descriptors:
                        finding_output = generate_provider_output_json(
                            finding.check_metadata.Provider,
                            finding,
                            audit_info,
                            "json",
                            file_descriptors["json"],
                        )
                        json.dump(
                            finding_output.dict(),
                            file_descriptors["json"],
                            indent=4,
                        )
                        file_descriptors["json"].write(",")

        else:  # No service resources in the whole account
            color = set_report_color("INFO")
            if not output_options.is_quiet and output_options.verbose:
                print(f"\t{color}INFO{Style.RESET_ALL} There are no resources")
        # Separator between findings and bar
        if output_options.is_quiet or output_options.verbose:
            print()
        if file_descriptors:
            # Close all file descriptors
            for file_descriptor in file_descriptors:
                file_descriptors.get(file_descriptor).close()
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def initialize_file_descriptor(
    filename: str,
    output_mode: str,
    audit_info: AWS_Audit_Info,
    format: Any = None,
) -> TextIOWrapper:
    """Open/Create the output file. If needed include headers or the required format"""
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

            if output_mode in ("csv", "ens_rd2022_aws", "cis_1.5_aws", "cis_1.4_aws"):
                # Format is the class model of the CSV format to print the headers
                csv_header = [x.upper() for x in generate_csv_fields(format)]
                csv_writer = DictWriter(
                    file_descriptor, fieldnames=csv_header, delimiter=";"
                )
                csv_writer.writeheader()

            if output_mode in ("json", "json-asff"):
                file_descriptor.write("[")
            if "html" in output_mode:
                add_html_header(file_descriptor, audit_info)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return file_descriptor


def fill_file_descriptors(output_modes, output_directory, output_filename, audit_info):
    try:
        file_descriptors = {}
        if output_modes:
            for output_mode in output_modes:
                if output_mode == "csv":
                    filename = f"{output_directory}/{output_filename}{csv_file_suffix}"
                    if isinstance(audit_info, AWS_Audit_Info):
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            audit_info,
                            Aws_Check_Output_CSV,
                        )
                    if isinstance(audit_info, Azure_Audit_Info):
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            audit_info,
                            Azure_Check_Output_CSV,
                        )
                    file_descriptors.update({output_mode: file_descriptor})

                if output_mode == "json":
                    filename = f"{output_directory}/{output_filename}{json_file_suffix}"
                    file_descriptor = initialize_file_descriptor(
                        filename, output_mode, audit_info
                    )
                    file_descriptors.update({output_mode: file_descriptor})

                if isinstance(audit_info, AWS_Audit_Info):

                    if output_mode == "json-asff":
                        filename = f"{output_directory}/{output_filename}{json_asff_file_suffix}"
                        file_descriptor = initialize_file_descriptor(
                            filename, output_mode, audit_info
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    if output_mode == "html":
                        filename = (
                            f"{output_directory}/{output_filename}{html_file_suffix}"
                        )
                        file_descriptor = initialize_file_descriptor(
                            filename, output_mode, audit_info
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    if output_mode == "ens_rd2022_aws":
                        filename = f"{output_directory}/{output_filename}_ens_rd2022_aws{csv_file_suffix}"
                        file_descriptor = initialize_file_descriptor(
                            filename,
                            output_mode,
                            audit_info,
                            Check_Output_CSV_ENS_RD2022,
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    if output_mode == "cis_1.5_aws":
                        filename = f"{output_directory}/{output_filename}_cis_1.5_aws{csv_file_suffix}"
                        file_descriptor = initialize_file_descriptor(
                            filename, output_mode, audit_info, Check_Output_CSV_CIS
                        )
                        file_descriptors.update({output_mode: file_descriptor})

                    if output_mode == "cis_1.4_aws":
                        filename = f"{output_directory}/{output_filename}_cis_1.4_aws{csv_file_suffix}"
                        file_descriptor = initialize_file_descriptor(
                            filename, output_mode, audit_info, Check_Output_CSV_CIS
                        )
                        file_descriptors.update({output_mode: file_descriptor})
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return file_descriptors


def set_report_color(status: str) -> str:
    """Return the color for a give result status"""
    color = ""
    if status == "PASS":
        color = Fore.GREEN
    elif status == "FAIL":
        color = Fore.RED
    elif status == "ERROR":
        color = Fore.BLACK
    elif status == "WARNING":
        color = orange_color
    elif status == "INFO":
        color = Fore.YELLOW
    else:
        raise Exception("Invalid Report Status. Must be PASS, FAIL, ERROR or WARNING")
    return color


def fill_json_asff(finding_output, audit_info, finding):
    # Check if there are no resources in the finding
    if finding.resource_id == "":
        finding.resource_id = "NONE_PROVIDED"
    finding_output.Id = f"prowler-{finding.check_metadata.CheckID}-{audit_info.audited_account}-{finding.region}-{hash_sha512(finding.resource_id)}"
    finding_output.ProductArn = f"arn:{audit_info.audited_partition}:securityhub:{finding.region}::product/prowler/prowler"
    finding_output.ProductFields = ProductFields(
        ProviderVersion=prowler_version, ProwlerResourceName=finding.resource_id
    )
    finding_output.GeneratorId = "prowler-" + finding.check_metadata.CheckID
    finding_output.AwsAccountId = audit_info.audited_account
    finding_output.Types = finding.check_metadata.CheckType
    finding_output.FirstObservedAt = (
        finding_output.UpdatedAt
    ) = finding_output.CreatedAt = timestamp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    finding_output.Severity = Severity(Label=finding.check_metadata.Severity.upper())
    finding_output.Title = finding.check_metadata.CheckTitle
    finding_output.Description = finding.check_metadata.Description
    finding_output.Resources = [
        Resource(
            Id=finding.resource_id,
            Type=finding.check_metadata.ResourceType,
            Partition=audit_info.audited_partition,
            Region=finding.region,
        )
    ]
    # Add ED to PASS or FAIL (PASSED/FAILED)
    finding_output.Compliance = Compliance(
        Status=finding.status + "ED",
        RelatedRequirements=finding.check_metadata.CheckType,
    )
    finding_output.Remediation = {
        "Recommendation": finding.check_metadata.Remediation.Recommendation
    }

    return finding_output


def close_json(output_filename, output_directory, mode):
    try:
        suffix = json_file_suffix
        if mode == "json-asff":
            suffix = json_asff_file_suffix
        filename = f"{output_directory}/{output_filename}{suffix}"
        file_descriptor = open_file(
            filename,
            "a",
        )
        # Replace last comma for square bracket if not empty
        if file_descriptor.tell() > 0:
            file_descriptor.seek(file_descriptor.tell() - 1, os.SEEK_SET)
            file_descriptor.truncate()
            file_descriptor.write("]")
        file_descriptor.close()
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit()


def send_to_s3_bucket(
    output_filename, output_directory, output_mode, output_bucket, audit_session
):
    try:
        # Get only last part of the path
        if output_mode == "csv":
            filename = f"{output_filename}{csv_file_suffix}"
        elif output_mode == "json":
            filename = f"{output_filename}{json_file_suffix}"
        elif output_mode == "json-asff":
            filename = f"{output_filename}{json_asff_file_suffix}"
        logger.info(f"Sending outputs to S3 bucket {output_bucket}")
        file_name = output_directory + "/" + filename
        bucket_name = output_bucket
        object_name = output_directory + "/" + output_mode + "/" + filename
        s3_client = audit_session.client("s3")
        s3_client.upload_file(file_name, bucket_name, object_name)

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit()


def display_summary_table(
    findings: list,
    audit_info,
    output_options: Provider_Output_Options,
    provider: str,
):
    output_directory = output_options.output_directory
    output_filename = output_options.output_filename
    try:
        if provider == "aws":
            entity_type = "Account"
            audited_entities = audit_info.audited_account
        elif provider == "azure":
            if audit_info.identity.domain:
                entity_type = "Tenant Domain"
                audited_entities = audit_info.identity.domain
            else:
                entity_type = "Tenant ID/s"
                audited_entities = " ".join(audit_info.identity.tenant_ids)

        if findings:
            current = {
                "Service": "",
                "Provider": "",
                "Total": 0,
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
            }
            findings_table = {
                "Provider": [],
                "Service": [],
                "Status": [],
                "Critical": [],
                "High": [],
                "Medium": [],
                "Low": [],
            }
            pass_count = fail_count = 0
            for finding in findings:
                # If new service and not first, add previous row
                if (
                    current["Service"] != finding.check_metadata.ServiceName
                    and current["Service"]
                ):

                    add_service_to_table(findings_table, current)

                    current["Total"] = current["Critical"] = current["High"] = current[
                        "Medium"
                    ] = current["Low"] = 0

                current["Service"] = finding.check_metadata.ServiceName
                current["Provider"] = finding.check_metadata.Provider

                current["Total"] += 1
                if finding.status == "PASS":
                    pass_count += 1
                elif finding.status == "FAIL":
                    fail_count += 1
                    if finding.check_metadata.Severity == "critical":
                        current["Critical"] += 1
                    elif finding.check_metadata.Severity == "high":
                        current["High"] += 1
                    elif finding.check_metadata.Severity == "medium":
                        current["Medium"] += 1
                    elif finding.check_metadata.Severity == "low":
                        current["Low"] += 1

            # Add final service

            add_service_to_table(findings_table, current)

            print("\nOverview Results:")
            overview_table = [
                [
                    f"{Fore.RED}{round(fail_count/len(findings)*100, 2)}% ({fail_count}) Failed{Style.RESET_ALL}",
                    f"{Fore.GREEN}{round(pass_count/len(findings)*100, 2)}% ({pass_count}) Passed{Style.RESET_ALL}",
                ]
            ]
            print(tabulate(overview_table, tablefmt="rounded_grid"))

            print(
                f"\n{entity_type} {Fore.YELLOW}{audited_entities}{Style.RESET_ALL} Scan Results (severity columns are for fails only):"
            )
            if provider == "azure":
                print(
                    f"\nSubscriptions scanned: {Fore.YELLOW}{' '.join(audit_info.identity.subscriptions.keys())}{Style.RESET_ALL}"
                )
            print(tabulate(findings_table, headers="keys", tablefmt="rounded_grid"))
            print(
                f"{Style.BRIGHT}* You only see here those services that contains resources.{Style.RESET_ALL}"
            )
            print("\nDetailed results are in:")
            if "html" in output_options.output_modes:
                print(f" - HTML: {output_directory}/{output_filename}.html")
            if "json-asff" in output_options.output_modes:
                print(f" - JSON-ASFF: {output_directory}/{output_filename}.asff.json")
            if "csv" in output_options.output_modes:
                print(f" - CSV: {output_directory}/{output_filename}.csv")
            if "json" in output_options.output_modes:
                print(f" - JSON: {output_directory}/{output_filename}.json")

        else:
            print(
                f"\n {Style.BRIGHT}There are no findings in {entity_type} {Fore.YELLOW}{audited_entities}{Style.RESET_ALL}\n"
            )

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
        )
        sys.exit()


def add_service_to_table(findings_table, current):
    if (
        current["Critical"] > 0
        or current["High"] > 0
        or current["Medium"] > 0
        or current["Low"] > 0
    ):
        total_fails = (
            current["Critical"] + current["High"] + current["Medium"] + current["Low"]
        )
        current["Status"] = f"{Fore.RED}FAIL ({total_fails}){Style.RESET_ALL}"
    else:
        current["Status"] = f"{Fore.GREEN}PASS ({current['Total']}){Style.RESET_ALL}"
    findings_table["Provider"].append(current["Provider"])
    findings_table["Service"].append(current["Service"])
    findings_table["Status"].append(current["Status"])
    findings_table["Critical"].append(
        f"{Fore.LIGHTRED_EX}{current['Critical']}{Style.RESET_ALL}"
    )
    findings_table["High"].append(f"{Fore.RED}{current['High']}{Style.RESET_ALL}")
    findings_table["Medium"].append(
        f"{Fore.YELLOW}{current['Medium']}{Style.RESET_ALL}"
    )
    findings_table["Low"].append(f"{Fore.BLUE}{current['Low']}{Style.RESET_ALL}")


def display_compliance_table(
    findings: list,
    bulk_checks_metadata: dict,
    compliance_framework: str,
    output_filename: str,
    output_directory: str,
):
    try:
        if "ens_rd2022_aws" in compliance_framework:
            marcos = {}
            ens_compliance_table = {
                "Proveedor": [],
                "Marco/Categoria": [],
                "Estado": [],
                "PYTEC": [],
                "Alto": [],
                "Medio": [],
                "Bajo": [],
            }
            pass_count = fail_count = 0
            for finding in findings:
                check = bulk_checks_metadata[finding.check_metadata.CheckID]
                check_compliances = check.Compliance
                for compliance in check_compliances:
                    if (
                        compliance.Framework == "ENS"
                        and compliance.Provider == "AWS"
                        and compliance.Version == "RD2022"
                    ):
                        for requirement in compliance.Requirements:
                            for attribute in requirement.Attributes:
                                marco_categoria = (
                                    f"{attribute['Marco']}/{attribute['Categoria']}"
                                )
                                # Check if Marco/Categoria exists
                                if marco_categoria not in marcos:
                                    marcos[marco_categoria] = {
                                        "Estado": f"{Fore.GREEN}CUMPLE{Style.RESET_ALL}",
                                        "Pytec": 0,
                                        "Alto": 0,
                                        "Medio": 0,
                                        "Bajo": 0,
                                    }
                                if finding.status == "FAIL":
                                    fail_count += 1
                                    marcos[marco_categoria][
                                        "Estado"
                                    ] = f"{Fore.RED}NO CUMPLE{Style.RESET_ALL}"
                                elif finding.status == "PASS":
                                    pass_count += 1
                                if attribute["Nivel"] == "pytec":
                                    marcos[marco_categoria]["Pytec"] += 1
                                elif attribute["Nivel"] == "alto":
                                    marcos[marco_categoria]["Alto"] += 1
                                elif attribute["Nivel"] == "medio":
                                    marcos[marco_categoria]["Medio"] += 1
                                elif attribute["Nivel"] == "bajo":
                                    marcos[marco_categoria]["Bajo"] += 1

            # Add results to table
            for marco in marcos:
                ens_compliance_table["Proveedor"].append("aws")
                ens_compliance_table["Marco/Categoria"].append(marco)
                ens_compliance_table["Estado"].append(marcos[marco]["Estado"])
                ens_compliance_table["PYTEC"].append(
                    f"{Fore.LIGHTRED_EX}{marcos[marco]['Pytec']}{Style.RESET_ALL}"
                )
                ens_compliance_table["Alto"].append(
                    f"{Fore.RED}{marcos[marco]['Alto']}{Style.RESET_ALL}"
                )
                ens_compliance_table["Medio"].append(
                    f"{Fore.YELLOW}{marcos[marco]['Medio']}{Style.RESET_ALL}"
                )
                ens_compliance_table["Bajo"].append(
                    f"{Fore.BLUE}{marcos[marco]['Bajo']}{Style.RESET_ALL}"
                )
            if fail_count + pass_count < 0:
                print(
                    f"\n {Style.BRIGHT}There are no resources for {Fore.YELLOW}ENS RD2022 - AWS{Style.RESET_ALL}.\n"
                )
            else:
                print(
                    f"\nEstado de Cumplimiento de {Fore.YELLOW}ENS RD2022 - AWS{Style.RESET_ALL}:"
                )
                overview_table = [
                    [
                        f"{Fore.RED}{round(fail_count/(fail_count+pass_count)*100, 2)}% ({fail_count}) NO CUMPLE{Style.RESET_ALL}",
                        f"{Fore.GREEN}{round(pass_count/(fail_count+pass_count)*100, 2)}% ({pass_count}) CUMPLE{Style.RESET_ALL}",
                    ]
                ]
                print(tabulate(overview_table, tablefmt="rounded_grid"))
                print(
                    f"\nResultados de {Fore.YELLOW}ENS RD2022 - AWS{Style.RESET_ALL}:"
                )
                print(
                    tabulate(
                        ens_compliance_table, headers="keys", tablefmt="rounded_grid"
                    )
                )
                print(
                    f"{Style.BRIGHT}* Solo aparece el Marco/Categoria que contiene resultados.{Style.RESET_ALL}"
                )
                print("\nResultados detallados en:")
                print(
                    f" - CSV: {output_directory}/{output_filename}_{compliance_framework[0]}.csv\n"
                )
        if "cis" in str(compliance_framework):
            sections = {}
            cis_compliance_table = {
                "Provider": [],
                "Section": [],
                "Level 1": [],
                "Level 2": [],
            }
            pass_count = fail_count = 0
            for finding in findings:
                check = bulk_checks_metadata[finding.check_metadata.CheckID]
                check_compliances = check.Compliance
                for compliance in check_compliances:
                    if compliance.Framework == "CIS-AWS" and compliance.Version in str(
                        compliance_framework
                    ):
                        compliance_version = compliance.Version
                        for requirement in compliance.Requirements:
                            for attribute in requirement.Attributes:
                                section = attribute["Section"]
                                # Check if Section exists
                                if section not in sections:
                                    sections[section] = {
                                        "Status": f"{Fore.GREEN}PASS{Style.RESET_ALL}",
                                        "Level 1": {"FAIL": 0, "PASS": 0},
                                        "Level 2": {"FAIL": 0, "PASS": 0},
                                    }
                                if finding.status == "FAIL":
                                    fail_count += 1
                                elif finding.status == "PASS":
                                    pass_count += 1
                                if attribute["Profile"] == "Level 1":
                                    if finding.status == "FAIL":
                                        sections[section]["Level 1"]["FAIL"] += 1
                                    else:
                                        sections[section]["Level 1"]["PASS"] += 1
                                elif attribute["Profile"] == "Level 2":
                                    if finding.status == "FAIL":
                                        sections[section]["Level 2"]["FAIL"] += 1
                                    else:
                                        sections[section]["Level 2"]["PASS"] += 1

            # Add results to table
            sections = dict(sorted(sections.items()))
            for section in sections:
                cis_compliance_table["Provider"].append("aws")
                cis_compliance_table["Section"].append(section)
                if sections[section]["Level 1"]["FAIL"] > 0:
                    cis_compliance_table["Level 1"].append(
                        f"{Fore.RED}FAIL({sections[section]['Level 1']['FAIL']}){Style.RESET_ALL}"
                    )
                else:
                    cis_compliance_table["Level 1"].append(
                        f"{Fore.GREEN}PASS({sections[section]['Level 1']['PASS']}){Style.RESET_ALL}"
                    )
                if sections[section]["Level 2"]["FAIL"] > 0:
                    cis_compliance_table["Level 2"].append(
                        f"{Fore.RED}FAIL({sections[section]['Level 2']['FAIL']}){Style.RESET_ALL}"
                    )
                else:
                    cis_compliance_table["Level 2"].append(
                        f"{Fore.GREEN}PASS({sections[section]['Level 2']['PASS']}){Style.RESET_ALL}"
                    )
            if fail_count + pass_count < 0:
                print(
                    f"\n {Style.BRIGHT}There are no resources for {Fore.YELLOW}{compliance.Framework}-{compliance.Version}{Style.RESET_ALL}.\n"
                )
            else:
                print(
                    f"\nCompliance Status of {Fore.YELLOW}{compliance.Framework}-{compliance_version}{Style.RESET_ALL} Framework:"
                )
                overview_table = [
                    [
                        f"{Fore.RED}{round(fail_count/(fail_count+pass_count)*100, 2)}% ({fail_count}) FAIL{Style.RESET_ALL}",
                        f"{Fore.GREEN}{round(pass_count/(fail_count+pass_count)*100, 2)}% ({pass_count}) PASS{Style.RESET_ALL}",
                    ]
                ]
                print(tabulate(overview_table, tablefmt="rounded_grid"))
                print(
                    f"\nFramework {Fore.YELLOW}{compliance.Framework}-{compliance_version}{Style.RESET_ALL} Results:"
                )
                print(
                    tabulate(
                        cis_compliance_table, headers="keys", tablefmt="rounded_grid"
                    )
                )
                print(
                    f"{Style.BRIGHT}* Only sections containing results appear.{Style.RESET_ALL}"
                )
                print("\nDetailed Results in:")
                print(
                    f" - CSV: {output_directory}/{output_filename}_{compliance_framework[0]}.csv\n"
                )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
        )
        sys.exit()


def add_html_header(file_descriptor, audit_info):
    try:
        if not audit_info.profile:
            audit_info.profile = "ENV"
        if isinstance(audit_info.audited_regions, list):
            audited_regions = " ".join(audit_info.audited_regions)
        elif not audit_info.audited_regions:
            audited_regions = "All Regions"
        else:
            audited_regions = audit_info.audited_regions
        file_descriptor.write(
            """
        <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <!-- Required meta tags -->
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <style>
    .read-more {color:#00f;}
    .bg-success-custom {background-color: #98dea7 !important;}
    .bg-danger {background-color: #f28484 !important;}
    </style>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css" integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk" crossorigin="anonymous">
    <!-- https://datatables.net/download/index with jQuery, DataTables, Buttons, SearchPanes, and Select //-->
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.3.0/sl-1.3.3/datatables.min.css"/>
    <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.10.0/css/all.css" integrity="sha384-AYmEC3Yw5cVb3ZcuHtOA93w35dYTsvhLPVnYs9eStHfGJvOvKxVfELGroGkvsg+p" crossorigin="anonymous"/>
    <style>
        .show-read-more .more-text{
            display: none;
        }
    </style>
    <title>Prowler - The Handy Cloud Security Tool</title>
    </head>
    <body>
    <div class="container-fluid">
        <div class="row mt-3">
        <div class="col-md-4">
            <div class="card">
            <div class="card-header">
                Report Information:
            </div>
            <ul class="list-group list-group-flush">
             <li class="list-group-item text-center">
            <a href="""
            + html_logo_url
            + """><img src="""
            + html_logo_img
            + """
            alt="prowler-logo"></a>
            </li>
                <li class="list-group-item">
                <div class="row">
                    <div class="col-md-auto">
                    <b>Version:</b> """
            + prowler_version
            + """
                    </div>
                </div>
                </li>
                <li class="list-group-item">
                <b>Parameters used:</b> """
            + " ".join(sys.argv[1:])
            + """
                </li>
                <li class="list-group-item">
                <b>Date:</b> """
            + timestamp.isoformat()
            + """
                </li>
            </ul>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card">
            <div class="card-header">
                Assessment Summary:
            </div>
            <ul class="list-group list-group-flush">
                <li class="list-group-item">
                <b>AWS Account:</b> """
            + audit_info.audited_account
            + """
                </li>
                <li class="list-group-item">
                <b>AWS-CLI Profile:</b> """
            + audit_info.profile
            + """
                </li>
                <li class="list-group-item">
                <b>Audited Regions:</b> """
            + audited_regions
            + """
                </li>
                <li class="list-group-item">
                <b>User Id:</b> """
            + audit_info.audited_user_id
            + """
                </li>
                <li class="list-group-item">
                <b>Caller Identity ARN:</b> """
            + audit_info.audited_identity_arn
            + """
                </li>
            </ul>
            </div>
        </div>
        <div class="row mt-3">
        <div class="col-md-12">
            <table class="table compact stripe row-border ordering" id="findingsTable" data-order='[[ 5, "asc" ]]' data-page-length='100'>
            <thead class="thead-light">
                <tr>
                <th scope="col">Status</th>
                <th scope="col">Severity</th>
                <th scope="col">Service Name</th>
                <th scope="col">Region</th>
                <th style="width:20%" scope="col">Check Title</th>
                <th scope="col">Resource ID</th>
                <th scope="col">Check Description</th>
                <th scope="col">Check ID</th>
                <th scope="col">Status Extended</th>
                <th scope="col">Risk</th>
                <th scope="col">Recomendation</th>
                <th style="5% width" scope="col">Recomendation URL</th>
                </tr>
            </thead>
            <tbody>
    """
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def fill_html(file_descriptor, audit_info, finding):
    row_class = "p-3 mb-2 bg-success-custom"
    if finding.status == "INFO":
        row_class = "table-info"
    elif finding.status == "FAIL":
        row_class = "table-danger"
    elif finding.status == "WARNING":
        row_class = "table-warning"
    file_descriptor.write(
        f"""
            <tr class="{row_class}">
                <td>{finding.status}</td>
                <td>{finding.check_metadata.Severity}</td>
                <td>{finding.check_metadata.ServiceName}</td>
                <td>{finding.region}</td>
                <td>{finding.check_metadata.CheckTitle}</td>
                <td>{finding.resource_id}</td>
                <td>{finding.check_metadata.Description}</td>
                <td>{finding.check_metadata.CheckID}</td>
                <td>{finding.status_extended}</td>
                <td><p class="show-read-more">{finding.check_metadata.Risk}</p></td>
                <td><p class="show-read-more">{finding.check_metadata.Remediation.Recommendation.Text}</p></td>
                <td><a class="read-more" href="{finding.check_metadata.Remediation.Recommendation.Url}"><i class="fas fa-external-link-alt"></i></a></td>
            </tr>
            """
    )


def add_html_footer(output_filename, output_directory):
    try:
        filename = f"{output_directory}/{output_filename}{html_file_suffix}"
        file_descriptor = open_file(
            filename,
            "a",
        )
        file_descriptor.write(
            """
</tbody>
        </table>
      </div>
    </div>
  </div>
  </div>
  <!-- Table search and paginator -->
  <!-- Optional JavaScript -->
  <!-- jQuery first, then Popper.js, then Bootstrap JS -->
  <script src="https://code.jquery.com/jquery-3.5.1.min.js" integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.bundle.min.js" integrity="sha384-1CmrxMRARb6aLqgBO7yyAxTOQE2AKb9GfXnEo760AUcUmFx3ibVJJAzGytlQcNXd" crossorigin="anonymous"></script>
  <!-- https://datatables.net/download/index with jQuery, DataTables, Buttons, SearchPanes, and Select //-->
  <script type="text/javascript" src="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.3.0/sl-1.3.3/datatables.min.js"></script>
  <script>
    $(document).ready(function(){
      // Initialise the table with 50 rows, and some search/filtering panes
      $('#findingsTable').DataTable( {
        lengthChange: true,
        buttons: [ 'copy', 'excel', 'pdf' ],
        lengthMenu: [ [50, 100, -1], [50, 100, "All"] ],
        searchPanes: {
            cascadePanes: true,
            viewTotal: true
        },
        dom: 'Plfrtip',
        columnDefs: [
          {
              searchPanes: {
                  show: true,
                  pagingType: 'numbers',
                  searching: true
              },
              targets: [0, 1, 2, 3, 4]
          }
        ]
      });
      var maxLength = 30;
      $(".show-read-more").each(function(){
        var myStr = $(this).text();
        if($.trim(myStr).length > maxLength){
          var newStr = myStr.substring(0, maxLength);
          var removedStr = myStr.substring(maxLength, $.trim(myStr).length);
          $(this).empty().html(newStr);
          $(this).append(' <a href="javascript:void(0);" class="read-more">read more...</a>');
          $(this).append('<span class="more-text">' + removedStr + '</span>');
        }
      });
      $(".read-more").click(function(){
        $(this).siblings(".more-text").contents().unwrap();
        $(this).remove();
      });
    });
    </script>
</body>
</html>
"""
        )
        file_descriptor.close()
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit()
