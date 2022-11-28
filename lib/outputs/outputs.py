import json
import os
import sys
from csv import DictWriter
from io import TextIOWrapper
from typing import Any

from colorama import Fore, Style
from tabulate import tabulate

from config.config import (
    csv_file_suffix,
    json_asff_file_suffix,
    json_file_suffix,
    orange_color,
    prowler_version,
    timestamp,
    timestamp_iso,
    timestamp_utc,
)
from lib.logger import logger
from lib.outputs.models import (
    Check_Output_CSV,
    Check_Output_CSV_ENS_RD2022,
    Check_Output_JSON,
    Check_Output_JSON_ASFF,
    Compliance,
    ProductFields,
    Resource,
    Severity,
)
from lib.utils.utils import file_exists, hash_sha512, open_file
from providers.aws.lib.allowlist.allowlist import is_allowlisted
from providers.aws.lib.security_hub.security_hub import send_to_security_hub


def report(check_findings, output_options, audit_info):
    # Sort check findings
    check_findings.sort(key=lambda x: x.region)

    # Generate the required output files
    # csv_fields = []
    file_descriptors = {}
    if output_options.output_modes:
        # We have to create the required output files
        file_descriptors = fill_file_descriptors(
            output_options.output_modes,
            output_options.output_directory,
            output_options.output_filename,
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
            if output_options.is_quiet and "FAIL" in finding.status:
                print(
                    f"\t{color}{finding.status}{Style.RESET_ALL} {finding.region}: {finding.status_extended}"
                )
            elif not output_options.is_quiet and output_options.verbose:
                print(
                    f"\t{color}{finding.status}{Style.RESET_ALL} {finding.region}: {finding.status_extended}"
                )
            if file_descriptors:
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
                                  requirement_description = requirement.Description
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

                  if "csv" in file_descriptors:
                      finding_output = Check_Output_CSV(
                          audit_info.audited_account,
                          audit_info.profile,
                          finding,
                          audit_info.organizations_metadata,
                      )
                      csv_writer = DictWriter(
                          file_descriptors["csv"],
                          fieldnames=generate_csv_fields(Check_Output_CSV),
                          delimiter=";",
                      )
                      csv_writer.writerow(finding_output.__dict__)

                  if "json" in file_descriptors:
                      finding_output = Check_Output_JSON(**finding.check_metadata.dict())
                      fill_json(finding_output, audit_info, finding)

                      json.dump(finding_output.dict(), file_descriptors["json"], indent=4)
                      file_descriptors["json"].write(",")

                  if "json-asff" in file_descriptors:
                      finding_output = Check_Output_JSON_ASFF()
                      fill_json_asff(finding_output, audit_info, finding)

                      json.dump(
                          finding_output.dict(), file_descriptors["json-asff"], indent=4
                      )
                      file_descriptors["json-asff"].write(",")

                  # Check if it is needed to send findings to security hub
                  if output_options.security_hub_enabled:
                      send_to_security_hub(
                          finding.region, finding_output, audit_info.audit_session
                      )
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


def initialize_file_descriptor(
    filename: str, output_mode: str, format: Any = None
) -> TextIOWrapper:
    """Open/Create the output file. If needed include headers or the required format"""

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

        if output_mode in ("csv", "ens_rd2022_aws"):
            # Format is the class model of the CSV format to print the headers
            csv_header = [x.upper() for x in generate_csv_fields(format)]
            csv_writer = DictWriter(
                file_descriptor, fieldnames=csv_header, delimiter=";"
            )
            csv_writer.writeheader()

        if output_mode in ("json", "json-asff"):
            file_descriptor = open_file(
                filename,
                "a",
            )
            file_descriptor.write("[")

    return file_descriptor


def fill_file_descriptors(output_modes, output_directory, output_filename):
    file_descriptors = {}
    if output_modes:
        for output_mode in output_modes:
            if output_mode == "csv":
                filename = f"{output_directory}/{output_filename}{csv_file_suffix}"
                file_descriptor = initialize_file_descriptor(
                    filename, output_mode, Check_Output_CSV
                )
                file_descriptors.update({output_mode: file_descriptor})

            if output_mode == "json":
                filename = f"{output_directory}/{output_filename}{json_file_suffix}"
                file_descriptor = initialize_file_descriptor(filename, output_mode)
                file_descriptors.update({output_mode: file_descriptor})

            if output_mode == "json-asff":
                filename = (
                    f"{output_directory}/{output_filename}{json_asff_file_suffix}"
                )
                file_descriptor = initialize_file_descriptor(filename, output_mode)
                file_descriptors.update({output_mode: file_descriptor})

            if output_mode == "ens_rd2022_aws":
                filename = f"{output_directory}/{output_filename}_ens_rd2022_aws{csv_file_suffix}"
                file_descriptor = initialize_file_descriptor(
                    filename, output_mode, Check_Output_CSV_ENS_RD2022
                )
                file_descriptors.update({output_mode: file_descriptor})

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


def generate_csv_fields(format: Any) -> list[str]:
    """Generates the CSV headers for the given class"""
    csv_fields = []
    for field in format.__dict__.get("__annotations__").keys():
        csv_fields.append(field)
    return csv_fields


def fill_json(finding_output, audit_info, finding):
    finding_output.AssessmentStartTime = timestamp_iso
    finding_output.FindingUniqueId = ""
    finding_output.Profile = audit_info.profile
    finding_output.AccountId = audit_info.audited_account
    if audit_info.organizations_metadata:
        finding_output.OrganizationsInfo = audit_info.organizations_metadata.__dict__
    finding_output.Region = finding.region
    finding_output.Status = finding.status
    finding_output.StatusExtended = finding.status_extended
    finding_output.ResourceId = finding.resource_id
    finding_output.ResourceArn = finding.resource_arn
    finding_output.ResourceDetails = finding.resource_details

    return finding_output


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
    output_filename: str,
    output_directory: str,
    provider: str,
):
    try:
        if provider == "aws":
            entity_type = "Account"
        elif provider == "azure":
            entity_type = "Tenant Domain"
        if findings:
            current = {
                "Service": "",
                "Provider": "",
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

                    current["Critical"] = current["High"] = current["Medium"] = current[
                        "Low"
                    ] = 0

                current["Service"] = finding.check_metadata.ServiceName
                current["Provider"] = finding.check_metadata.Provider

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
                f"\n{entity_type} {Fore.YELLOW}{audit_info.audited_account}{Style.RESET_ALL} Scan Results (severity columns are for fails only):"
            )
            print(tabulate(findings_table, headers="keys", tablefmt="rounded_grid"))
            print(
                f"{Style.BRIGHT}* You only see here those services that contains resources.{Style.RESET_ALL}"
            )
            print("\nDetailed results are in:")
            print(f" - CSV: {output_directory}/{output_filename}.csv")
            print(f" - JSON: {output_directory}/{output_filename}.json\n")

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
            print(f"\nResultados de {Fore.YELLOW}ENS RD2022 - AWS{Style.RESET_ALL}:")
            print(
                tabulate(ens_compliance_table, headers="keys", tablefmt="rounded_grid")
            )
            print(
                f"{Style.BRIGHT}* Solo aparece el Marco/Categoria que contiene resultados.{Style.RESET_ALL}"
            )
            print("\nResultados detallados en:")
            print(
                f" - CSV: {output_directory}/{output_filename}_{compliance_framework[0]}.csv\n"
            )

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
        )
        sys.exit()
