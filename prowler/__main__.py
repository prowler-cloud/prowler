#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from os import environ

from colorama import Fore, Style
from colorama import init as colorama_init

from prowler.config.config import (
    csv_file_suffix,
    get_available_compliance_frameworks,
    html_file_suffix,
    json_asff_file_suffix,
    json_ocsf_file_suffix,
)
from prowler.lib.banner import print_banner
from prowler.lib.check.check import (
    exclude_checks_to_run,
    exclude_services_to_run,
    execute_checks,
    list_categories,
    list_checks_json,
    list_fixers,
    list_services,
    parse_checks_from_folder,
    print_categories,
    print_checks,
    print_compliance_frameworks,
    print_compliance_requirements,
    print_fixers,
    print_services,
    remove_custom_checks_module,
    run_fixer,
)
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.custom_checks_metadata import (
    parse_custom_checks_metadata_file,
    update_checks_metadata,
)
from prowler.lib.check.models import CheckMetadata
from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.lib.logger import logger, set_logging_config
from prowler.lib.outputs.asff.asff import ASFF
from prowler.lib.outputs.compliance.aws_well_architected.aws_well_architected import (
    AWSWellArchitected,
)
from prowler.lib.outputs.compliance.cis.cis_aws import AWSCIS
from prowler.lib.outputs.compliance.cis.cis_azure import AzureCIS
from prowler.lib.outputs.compliance.cis.cis_gcp import GCPCIS
from prowler.lib.outputs.compliance.cis.cis_kubernetes import KubernetesCIS
from prowler.lib.outputs.compliance.compliance import display_compliance_table
from prowler.lib.outputs.compliance.ens.ens_aws import AWSENS
from prowler.lib.outputs.compliance.ens.ens_azure import AzureENS
from prowler.lib.outputs.compliance.ens.ens_gcp import GCPENS
from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.compliance.iso27001.iso27001_aws import AWSISO27001
from prowler.lib.outputs.compliance.kisa_ismsp.kisa_ismsp_aws import AWSKISAISMSP
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_aws import AWSMitreAttack
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_azure import (
    AzureMitreAttack,
)
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_gcp import GCPMitreAttack
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.html.html import HTML
from prowler.lib.outputs.ocsf.ocsf import OCSF
from prowler.lib.outputs.outputs import extract_findings_statistics
from prowler.lib.outputs.slack.slack import Slack
from prowler.lib.outputs.summary_table import display_summary_table
from prowler.providers.aws.lib.s3.s3 import S3
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHub
from prowler.providers.aws.models import AWSOutputOptions
from prowler.providers.azure.models import AzureOutputOptions
from prowler.providers.common.provider import Provider
from prowler.providers.common.quick_inventory import run_provider_quick_inventory
from prowler.providers.gcp.models import GCPOutputOptions
from prowler.providers.kubernetes.models import KubernetesOutputOptions


def prowler():
    # Parse Arguments
    # Refactor(CLI)
    parser = ProwlerArgumentParser()
    args = parser.parse()

    # Save Arguments
    provider = args.provider
    if provider == "dashboard":
        from dashboard import DASHBOARD_ARGS
        from dashboard.__main__ import dashboard

        sys.exit(dashboard.run(**DASHBOARD_ARGS))

    checks = args.check
    excluded_checks = args.excluded_check
    excluded_services = args.excluded_service
    services = args.service
    categories = args.category
    checks_file = args.checks_file
    checks_folder = args.checks_folder
    severities = args.severity
    compliance_framework = args.compliance
    custom_checks_metadata_file = args.custom_checks_metadata_file
    default_execution = (
        not checks
        and not services
        and not categories
        and not excluded_checks
        and not excluded_services
        and not severities
        and not checks_file
        and not checks_folder
    )

    if args.no_color:
        colorama_init(strip=True)

    if not args.no_banner:
        legend = args.verbose or getattr(args, "fixer", None)
        print_banner(legend)

    # We treat the compliance framework as another output format
    if compliance_framework:
        args.output_formats.extend(compliance_framework)
    # If no input compliance framework, set all, unless a specific service or check is input
    elif default_execution:
        args.output_formats.extend(get_available_compliance_frameworks(provider))

    # Set Logger configuration
    set_logging_config(args.log_level, args.log_file, args.only_logs)

    if args.list_services:
        print_services(list_services(provider))
        sys.exit()

    if args.list_fixer:
        print_fixers(list_fixers(provider))
        sys.exit()

    # Load checks metadata
    logger.debug("Loading checks metadata from .metadata.json files")
    bulk_checks_metadata = CheckMetadata.get_bulk(provider)

    if args.list_categories:
        print_categories(list_categories(bulk_checks_metadata))
        sys.exit()

    bulk_compliance_frameworks = {}
    # Load compliance frameworks
    logger.debug("Loading compliance frameworks from .json files")

    bulk_compliance_frameworks = Compliance.get_bulk(provider)
    # Complete checks metadata with the compliance framework specification
    bulk_checks_metadata = update_checks_metadata_with_compliance(
        bulk_compliance_frameworks, bulk_checks_metadata
    )

    # Update checks metadata if the --custom-checks-metadata-file is present
    custom_checks_metadata = None
    if custom_checks_metadata_file:
        custom_checks_metadata = parse_custom_checks_metadata_file(
            provider, custom_checks_metadata_file
        )
        bulk_checks_metadata = update_checks_metadata(
            bulk_checks_metadata, custom_checks_metadata
        )

    if args.list_compliance:
        print_compliance_frameworks(bulk_compliance_frameworks)
        sys.exit()
    if args.list_compliance_requirements:
        print_compliance_requirements(
            bulk_compliance_frameworks, args.list_compliance_requirements
        )
        sys.exit()

    # Load checks to execute
    checks_to_execute = load_checks_to_execute(
        bulk_checks_metadata=bulk_checks_metadata,
        bulk_compliance_frameworks=bulk_compliance_frameworks,
        checks_file=checks_file,
        check_list=checks,
        service_list=services,
        severities=severities,
        compliance_frameworks=compliance_framework,
        categories=categories,
        provider=provider,
    )

    # if --list-checks-json, dump a json file and exit
    if args.list_checks_json:
        print(list_checks_json(provider, sorted(checks_to_execute)))
        sys.exit()

    # If -l/--list-checks passed as argument, print checks to execute and quit
    if args.list_checks:
        print_checks(provider, sorted(checks_to_execute), bulk_checks_metadata)
        sys.exit()

    # Provider to scan
    Provider.init_global_provider(args)
    global_provider = Provider.get_global_provider()

    # Print Provider Credentials
    if not args.only_logs:
        global_provider.print_credentials()

    # Import custom checks from folder
    if checks_folder:
        custom_checks = parse_checks_from_folder(global_provider, checks_folder)
        # Workaround to be able to execute custom checks alongside all checks if nothing is explicitly set
        if (
            not checks_file
            and not checks
            and not services
            and not severities
            and not compliance_framework
            and not categories
        ):
            checks_to_execute.update(custom_checks)

    # Exclude checks if -e/--excluded-checks
    if excluded_checks:
        checks_to_execute = exclude_checks_to_run(checks_to_execute, excluded_checks)

    # Exclude services if --excluded-services
    if excluded_services:
        checks_to_execute = exclude_services_to_run(
            checks_to_execute, excluded_services, provider
        )

    # Once the provider is set and we have the eventual checks based on the resource identifier,
    # it is time to check what Prowler's checks are going to be executed
    checks_from_resources = global_provider.get_checks_to_execute_by_audit_resources()
    # Intersect checks from resources with checks to execute so we only run the checks that apply to the resources with the specified ARNs or tags
    if getattr(args, "resource_arn", None) or getattr(args, "resource_tag", None):
        checks_to_execute = checks_to_execute.intersection(checks_from_resources)

    # Sort final check list
    checks_to_execute = sorted(checks_to_execute)

    # Setup Output Options
    if provider == "aws":
        output_options = AWSOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "azure":
        output_options = AzureOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "gcp":
        output_options = GCPOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "kubernetes":
        output_options = KubernetesOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )

    # Run the quick inventory for the provider if available
    if hasattr(args, "quick_inventory") and args.quick_inventory:
        run_provider_quick_inventory(global_provider, args)
        sys.exit()

    # Execute checks
    findings = []

    if len(checks_to_execute):
        findings = execute_checks(
            checks_to_execute,
            global_provider,
            custom_checks_metadata,
            args.config_file,
            output_options,
        )
    else:
        logger.error(
            "There are no checks to execute. Please, check your input arguments"
        )

    # Prowler Fixer
    if output_options.fixer:
        print(f"{Style.BRIGHT}\nRunning Prowler Fixer, please wait...{Style.RESET_ALL}")
        # Check if there are any FAIL findings
        if any("FAIL" in finding.status for finding in findings):
            fixed_findings = run_fixer(findings)
            if not fixed_findings:
                print(
                    f"{Style.BRIGHT}{Fore.RED}\nThere were findings to fix, but the fixer failed or it is not implemented for those findings yet. {Style.RESET_ALL}\n"
                )
            else:
                print(
                    f"{Style.BRIGHT}{Fore.GREEN}\n{fixed_findings} findings fixed!{Style.RESET_ALL}\n"
                )
        else:
            print(f"{Style.BRIGHT}{Fore.GREEN}\nNo findings to fix!{Style.RESET_ALL}\n")
        sys.exit()

    # Extract findings stats
    stats = extract_findings_statistics(findings)

    if args.slack:
        # TODO: this should be also in a config file
        if "SLACK_API_TOKEN" in environ and (
            "SLACK_CHANNEL_NAME" in environ or "SLACK_CHANNEL_ID" in environ
        ):

            token = environ["SLACK_API_TOKEN"]
            channel = (
                environ["SLACK_CHANNEL_NAME"]
                if "SLACK_CHANNEL_NAME" in environ
                else environ["SLACK_CHANNEL_ID"]
            )
            prowler_args = " ".join(sys.argv[1:])
            slack = Slack(token, channel, global_provider)
            _ = slack.send(stats, prowler_args)
        else:
            # Refactor(CLI)
            logger.critical(
                "Slack integration needs SLACK_API_TOKEN and SLACK_CHANNEL_NAME environment variables (see more in https://docs.prowler.cloud/en/latest/tutorials/integrations/#slack)."
            )
            sys.exit(1)

    # Outputs
    # TODO: this part is needed since the checks generates a Check_Report_XXX and the output uses Finding
    # This will be refactored for the outputs generate directly the Finding
    finding_outputs = [
        Finding.generate_output(global_provider, finding, output_options)
        for finding in findings
    ]

    generated_outputs = {"regular": [], "compliance": []}

    if args.output_formats:
        for mode in args.output_formats:
            filename = (
                f"{output_options.output_directory}/"
                f"{output_options.output_filename}"
            )
            if mode == "csv":
                csv_output = CSV(
                    findings=finding_outputs,
                    create_file_descriptor=True,
                    file_path=f"{filename}{csv_file_suffix}",
                )
                generated_outputs["regular"].append(csv_output)
                # Write CSV Finding Object to file
                csv_output.batch_write_data_to_file()

            if mode == "json-asff":
                asff_output = ASFF(
                    findings=finding_outputs,
                    create_file_descriptor=True,
                    file_path=f"{filename}{json_asff_file_suffix}",
                )
                generated_outputs["regular"].append(asff_output)
                # Write ASFF Finding Object to file
                asff_output.batch_write_data_to_file()

            if mode == "json-ocsf":
                json_output = OCSF(
                    findings=finding_outputs,
                    create_file_descriptor=True,
                    file_path=f"{filename}{json_ocsf_file_suffix}",
                )
                generated_outputs["regular"].append(json_output)
                json_output.batch_write_data_to_file()
            if mode == "html":
                html_output = HTML(
                    findings=finding_outputs,
                    create_file_descriptor=True,
                    file_path=f"{filename}{html_file_suffix}",
                )
                generated_outputs["regular"].append(html_output)
                html_output.batch_write_data_to_file(
                    provider=global_provider, stats=stats
                )

    # Compliance Frameworks
    input_compliance_frameworks = set(output_options.output_modes).intersection(
        get_available_compliance_frameworks(provider)
    )
    if provider == "aws":
        for compliance_name in input_compliance_frameworks:
            if compliance_name.startswith("cis_"):
                # Generate CIS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                cis = AWSCIS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(cis)
                cis.batch_write_data_to_file()
            elif compliance_name == "mitre_attack_aws":
                # Generate MITRE ATT&CK Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                mitre_attack = AWSMitreAttack(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(mitre_attack)
                mitre_attack.batch_write_data_to_file()
            elif compliance_name.startswith("ens_"):
                # Generate ENS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                ens = AWSENS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(ens)
                ens.batch_write_data_to_file()
            elif compliance_name.startswith("aws_well_architected_framework"):
                # Generate AWS Well-Architected Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                aws_well_architected = AWSWellArchitected(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(aws_well_architected)
                aws_well_architected.batch_write_data_to_file()
            elif compliance_name.startswith("iso27001_"):
                # Generate ISO27001 Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                iso27001 = AWSISO27001(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(iso27001)
                iso27001.batch_write_data_to_file()
            elif compliance_name.startswith("kisa"):
                # Generate KISA-ISMS-P Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                kisa_ismsp = AWSKISAISMSP(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(kisa_ismsp)
                kisa_ismsp.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(generic_compliance)
                generic_compliance.batch_write_data_to_file()

    elif provider == "azure":
        for compliance_name in input_compliance_frameworks:
            if compliance_name.startswith("cis_"):
                # Generate CIS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                cis = AzureCIS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(cis)
                cis.batch_write_data_to_file()
            elif compliance_name == "mitre_attack_azure":
                # Generate MITRE ATT&CK Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                mitre_attack = AzureMitreAttack(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(mitre_attack)
                mitre_attack.batch_write_data_to_file()
            elif compliance_name.startswith("ens_"):
                # Generate ENS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                ens = AzureENS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(ens)
                ens.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(generic_compliance)
                generic_compliance.batch_write_data_to_file()

    elif provider == "gcp":
        for compliance_name in input_compliance_frameworks:
            if compliance_name.startswith("cis_"):
                # Generate CIS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                cis = GCPCIS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(cis)
                cis.batch_write_data_to_file()
            elif compliance_name == "mitre_attack_gcp":
                # Generate MITRE ATT&CK Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                mitre_attack = GCPMitreAttack(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(mitre_attack)
                mitre_attack.batch_write_data_to_file()
            elif compliance_name.startswith("ens_"):
                # Generate ENS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                ens = GCPENS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(ens)
                ens.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(generic_compliance)
                generic_compliance.batch_write_data_to_file()

    elif provider == "kubernetes":
        for compliance_name in input_compliance_frameworks:
            if compliance_name.startswith("cis_"):
                # Generate CIS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                cis = KubernetesCIS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(cis)
                cis.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    create_file_descriptor=True,
                    file_path=filename,
                )
                generated_outputs["compliance"].append(generic_compliance)
                generic_compliance.batch_write_data_to_file()

    # AWS Security Hub Integration
    if provider == "aws":
        # Send output to S3 if needed (-B / -D) for all the output formats
        if args.output_bucket or args.output_bucket_no_assume:
            output_bucket = args.output_bucket
            bucket_session = global_provider.session.current_session
            # Check if -D was input
            if args.output_bucket_no_assume:
                output_bucket = args.output_bucket_no_assume
                bucket_session = global_provider.session.original_session
            s3 = S3(
                session=bucket_session,
                bucket_name=output_bucket,
                output_directory=args.output_directory,
            )
            s3.send_to_bucket(generated_outputs)
        if args.security_hub:
            print(
                f"{Style.BRIGHT}\nSending findings to AWS Security Hub, please wait...{Style.RESET_ALL}"
            )

            security_hub_regions = (
                global_provider.get_available_aws_service_regions(
                    "securityhub",
                    global_provider.identity.partition,
                    global_provider.identity.audited_regions,
                )
                if not global_provider.identity.audited_regions
                else global_provider.identity.audited_regions
            )

            security_hub = SecurityHub(
                aws_account_id=global_provider.identity.account,
                aws_partition=global_provider.identity.partition,
                aws_session=global_provider.session.current_session,
                findings=asff_output.data,
                send_only_fails=output_options.send_sh_only_fails,
                aws_security_hub_available_regions=security_hub_regions,
            )
            # Send the findings to Security Hub
            findings_sent_to_security_hub = security_hub.batch_send_to_security_hub()
            print(
                f"{Style.BRIGHT}{Fore.GREEN}\n{findings_sent_to_security_hub} findings sent to AWS Security Hub!{Style.RESET_ALL}"
            )

            # Resolve previous fails of Security Hub
            if not args.skip_sh_update:
                print(
                    f"{Style.BRIGHT}\nArchiving previous findings in AWS Security Hub, please wait...{Style.RESET_ALL}"
                )
                findings_archived_in_security_hub = (
                    security_hub.archive_previous_findings()
                )
                print(
                    f"{Style.BRIGHT}{Fore.GREEN}\n{findings_archived_in_security_hub} findings archived in AWS Security Hub!{Style.RESET_ALL}"
                )

    # Display summary table
    if not args.only_logs:
        display_summary_table(
            findings,
            global_provider,
            output_options,
        )
        # Only display compliance table if there are findings (not all MANUAL) and it is a default execution
        if (
            findings and not all(finding.status == "MANUAL" for finding in findings)
        ) and default_execution:
            compliance_overview = False
            if not compliance_framework:
                compliance_framework = get_available_compliance_frameworks(provider)
                if (
                    compliance_framework
                ):  # If there are compliance frameworks, print compliance overview
                    compliance_overview = True
            for compliance in sorted(compliance_framework):
                # Display compliance table
                display_compliance_table(
                    findings,
                    bulk_checks_metadata,
                    compliance,
                    output_options.output_filename,
                    output_options.output_directory,
                    compliance_overview,
                )
            if compliance_overview:
                print(
                    f"\nDetailed compliance results are in {Fore.YELLOW}{output_options.output_directory}/compliance/{Style.RESET_ALL}\n"
                )

    # If custom checks were passed, remove the modules
    if checks_folder:
        remove_custom_checks_module(checks_folder, provider)

    # If there are failed findings exit code 3, except if -z is input
    if (
        not args.ignore_exit_code_3
        and stats["total_fail"] > 0
        and not stats["all_fails_are_muted"]
    ):
        sys.exit(3)


if __name__ == "__main__":
    prowler()
