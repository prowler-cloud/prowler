#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import tempfile
from os import environ

import requests
from colorama import Fore, Style
from colorama import init as colorama_init

from prowler.config.config import (
    EXTERNAL_TOOL_PROVIDERS,
    cloud_api_base_url,
    csv_file_suffix,
    get_available_compliance_frameworks,
    html_file_suffix,
    json_asff_file_suffix,
    json_ocsf_file_suffix,
    orange_color,
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
    load_custom_checks_metadata,
    parse_checks_from_file,
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
from prowler.lib.outputs.compliance.c5.c5_aws import AWSC5
from prowler.lib.outputs.compliance.c5.c5_azure import AzureC5
from prowler.lib.outputs.compliance.c5.c5_gcp import GCPC5
from prowler.lib.outputs.compliance.ccc.ccc_aws import CCC_AWS
from prowler.lib.outputs.compliance.ccc.ccc_azure import CCC_Azure
from prowler.lib.outputs.compliance.ccc.ccc_gcp import CCC_GCP
from prowler.lib.outputs.compliance.cis.cis_alibabacloud import AlibabaCloudCIS
from prowler.lib.outputs.compliance.cis.cis_aws import AWSCIS
from prowler.lib.outputs.compliance.cis.cis_azure import AzureCIS
from prowler.lib.outputs.compliance.cis.cis_gcp import GCPCIS
from prowler.lib.outputs.compliance.cis.cis_github import GithubCIS
from prowler.lib.outputs.compliance.cis.cis_kubernetes import KubernetesCIS
from prowler.lib.outputs.compliance.cis.cis_m365 import M365CIS
from prowler.lib.outputs.compliance.cis.cis_oraclecloud import OracleCloudCIS
from prowler.lib.outputs.compliance.compliance import display_compliance_table
from prowler.lib.outputs.compliance.csa.csa_alibabacloud import AlibabaCloudCSA
from prowler.lib.outputs.compliance.csa.csa_aws import AWSCSA
from prowler.lib.outputs.compliance.csa.csa_azure import AzureCSA
from prowler.lib.outputs.compliance.csa.csa_gcp import GCPCSA
from prowler.lib.outputs.compliance.csa.csa_oraclecloud import OracleCloudCSA
from prowler.lib.outputs.compliance.ens.ens_aws import AWSENS
from prowler.lib.outputs.compliance.ens.ens_azure import AzureENS
from prowler.lib.outputs.compliance.ens.ens_gcp import GCPENS
from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.compliance.iso27001.iso27001_aws import AWSISO27001
from prowler.lib.outputs.compliance.iso27001.iso27001_azure import AzureISO27001
from prowler.lib.outputs.compliance.iso27001.iso27001_gcp import GCPISO27001
from prowler.lib.outputs.compliance.iso27001.iso27001_kubernetes import (
    KubernetesISO27001,
)
from prowler.lib.outputs.compliance.iso27001.iso27001_m365 import M365ISO27001
from prowler.lib.outputs.compliance.iso27001.iso27001_nhn import NHNISO27001
from prowler.lib.outputs.compliance.kisa_ismsp.kisa_ismsp_aws import AWSKISAISMSP
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_aws import AWSMitreAttack
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_azure import (
    AzureMitreAttack,
)
from prowler.lib.outputs.compliance.mitre_attack.mitre_attack_gcp import GCPMitreAttack
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_alibaba import (
    ProwlerThreatScoreAlibaba,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_aws import (
    ProwlerThreatScoreAWS,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_azure import (
    ProwlerThreatScoreAzure,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_gcp import (
    ProwlerThreatScoreGCP,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_kubernetes import (
    ProwlerThreatScoreKubernetes,
)
from prowler.lib.outputs.compliance.prowler_threatscore.prowler_threatscore_m365 import (
    ProwlerThreatScoreM365,
)
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.html.html import HTML
from prowler.lib.outputs.ocsf.ingestion import send_ocsf_to_api
from prowler.lib.outputs.ocsf.ocsf import OCSF
from prowler.lib.outputs.outputs import extract_findings_statistics, report
from prowler.lib.outputs.slack.slack import Slack
from prowler.lib.outputs.summary_table import display_summary_table
from prowler.providers.alibabacloud.models import AlibabaCloudOutputOptions
from prowler.providers.aws.lib.s3.s3 import S3
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHub
from prowler.providers.aws.models import AWSOutputOptions
from prowler.providers.azure.models import AzureOutputOptions
from prowler.providers.cloudflare.models import CloudflareOutputOptions
from prowler.providers.common.provider import Provider
from prowler.providers.common.quick_inventory import run_provider_quick_inventory
from prowler.providers.gcp.models import GCPOutputOptions
from prowler.providers.github.models import GithubOutputOptions
from prowler.providers.iac.models import IACOutputOptions
from prowler.providers.image.exceptions.exceptions import ImageBaseException
from prowler.providers.image.models import ImageOutputOptions
from prowler.providers.kubernetes.models import KubernetesOutputOptions
from prowler.providers.llm.models import LLMOutputOptions
from prowler.providers.m365.models import M365OutputOptions
from prowler.providers.mongodbatlas.models import MongoDBAtlasOutputOptions
from prowler.providers.nhn.models import NHNOutputOptions
from prowler.providers.openstack.models import OpenStackOutputOptions
from prowler.providers.oraclecloud.models import OCIOutputOptions


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
    excluded_checks_file = args.excluded_checks_file
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

    # Load custom checks metadata before validation
    if checks_folder:
        custom_folder_metadata = load_custom_checks_metadata(checks_folder)
        bulk_checks_metadata.update(custom_folder_metadata)

    if args.list_categories:
        print_categories(list_categories(bulk_checks_metadata))
        sys.exit()

    bulk_compliance_frameworks = {}
    # Load compliance frameworks
    logger.debug("Loading compliance frameworks from .json files")

    # Skip compliance frameworks for external-tool providers
    if provider not in EXTERNAL_TOOL_PROVIDERS:
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

    # Skip service and check loading for external-tool providers
    if provider not in EXTERNAL_TOOL_PROVIDERS:
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
            checks_to_execute = exclude_checks_to_run(
                checks_to_execute, excluded_checks
            )

        # Exclude checks if --excluded-checks-file
        if excluded_checks_file:
            excluded_checks_from_file = parse_checks_from_file(
                excluded_checks_file, provider
            )
            checks_to_execute = exclude_checks_to_run(
                checks_to_execute, list(excluded_checks_from_file)
            )

        # Exclude services if --excluded-services
        if excluded_services:
            checks_to_execute = exclude_services_to_run(
                checks_to_execute, excluded_services, provider
            )

        # Once the provider is set and we have the eventual checks based on the resource identifier,
        # it is time to check what Prowler's checks are going to be executed
        checks_from_resources = (
            global_provider.get_checks_to_execute_by_audit_resources()
        )
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
    elif provider == "github":
        output_options = GithubOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "cloudflare":
        output_options = CloudflareOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "m365":
        output_options = M365OutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "mongodbatlas":
        output_options = MongoDBAtlasOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "nhn":
        output_options = NHNOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "iac":
        output_options = IACOutputOptions(args, bulk_checks_metadata)
    elif provider == "image":
        output_options = ImageOutputOptions(args, bulk_checks_metadata)
    elif provider == "llm":
        output_options = LLMOutputOptions(args, bulk_checks_metadata)
    elif provider == "oraclecloud":
        output_options = OCIOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "alibabacloud":
        output_options = AlibabaCloudOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )
    elif provider == "openstack":
        output_options = OpenStackOutputOptions(
            args, bulk_checks_metadata, global_provider.identity
        )

    # Run the quick inventory for the provider if available
    if hasattr(args, "quick_inventory") and args.quick_inventory:
        run_provider_quick_inventory(global_provider, args)
        sys.exit()

    # Execute checks
    findings = []

    if provider in EXTERNAL_TOOL_PROVIDERS:
        # For external-tool providers, run the scan directly
        if provider == "llm":

            def streaming_callback(findings_batch):
                """Callback to report findings as they are processed in real-time."""
                report(findings_batch, global_provider, output_options)

            findings = global_provider.run_scan(streaming_callback=streaming_callback)
        else:
            # Original behavior for IAC or non-verbose LLM
            try:
                findings = global_provider.run()
            except ImageBaseException as error:
                logger.critical(f"{error}")
                sys.exit(1)
            # Note: IaC doesn't support granular progress tracking since Trivy runs as a black box
            # and returns all findings at once. Progress tracking would just be 0% → 100%.

            # Filter findings by status if specified
            if hasattr(args, "status") and args.status:
                findings = [f for f in findings if f.status in args.status]
            # Report findings for verbose output
            report(findings, global_provider, output_options)
    elif len(checks_to_execute):
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

    # Outputs
    # TODO: this part is needed since the checks generates a Check_Report_XXX and the output uses Finding
    # This will be refactored for the outputs generate directly the Finding
    finding_outputs = []
    for finding in findings:
        try:
            finding_outputs.append(
                Finding.generate_output(global_provider, finding, output_options)
            )
        except Exception:
            continue

    # Extract findings stats
    stats = extract_findings_statistics(finding_outputs)

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
                "Slack integration needs SLACK_API_TOKEN and SLACK_CHANNEL_NAME environment variables (see more in https://docs.prowler.com/user-guide/cli/tutorials/integrations#configuration-of-the-integration-with-slack)."
            )
            sys.exit(1)

    generated_outputs = {"regular": [], "compliance": []}
    ocsf_output = None

    if args.output_formats:
        for mode in args.output_formats:
            filename = (
                f"{output_options.output_directory}/{output_options.output_filename}"
            )
            if mode == "csv":
                csv_output = CSV(
                    findings=finding_outputs,
                    file_path=f"{filename}{csv_file_suffix}",
                )
                generated_outputs["regular"].append(csv_output)
                # Write CSV Finding Object to file
                csv_output.batch_write_data_to_file()

            if mode == "json-asff":
                asff_output = ASFF(
                    findings=finding_outputs,
                    file_path=f"{filename}{json_asff_file_suffix}",
                )
                generated_outputs["regular"].append(asff_output)
                # Write ASFF Finding Object to file
                asff_output.batch_write_data_to_file()

            if mode == "json-ocsf":
                json_output = OCSF(
                    findings=finding_outputs,
                    file_path=f"{filename}{json_ocsf_file_suffix}",
                )
                generated_outputs["regular"].append(json_output)
                ocsf_output = json_output
                json_output.batch_write_data_to_file()
            if mode == "html":
                html_output = HTML(
                    findings=finding_outputs,
                    file_path=f"{filename}{html_file_suffix}",
                )
                generated_outputs["regular"].append(html_output)
                html_output.batch_write_data_to_file(
                    provider=global_provider, stats=stats
                )

    if getattr(args, "export_ocsf", False):
        if not ocsf_output or not getattr(ocsf_output, "file_path", None):
            tmp_ocsf = tempfile.NamedTemporaryFile(
                suffix=json_ocsf_file_suffix, delete=False
            )
            ocsf_output = OCSF(
                findings=finding_outputs,
                file_path=tmp_ocsf.name,
            )
            tmp_ocsf.close()
            ocsf_output.batch_write_data_to_file()
        print(
            f"{Style.BRIGHT}\nExporting OCSF to Prowler Cloud, please wait...{Style.RESET_ALL}"
        )
        try:
            response = send_ocsf_to_api(ocsf_output.file_path)
        except ValueError:
            logger.warning(
                "OCSF export skipped: no API key configured. "
                "Set the PROWLER_API_KEY environment variable to enable it. "
                f"Scan results were saved to {ocsf_output.file_path}"
            )
        except requests.ConnectionError:
            logger.warning(
                "OCSF export skipped: could not reach the Prowler Cloud API at "
                f"{cloud_api_base_url}. Check the URL and your network connection. "
                f"Scan results were saved to {ocsf_output.file_path}"
            )
        except requests.HTTPError as http_err:
            logger.warning(
                f"OCSF export failed: the API returned HTTP {http_err.response.status_code}. "
                "Verify your API key is valid and has the right permissions. "
                f"Scan results were saved to {ocsf_output.file_path}"
            )
        except Exception as error:
            logger.warning(
                f"OCSF export failed unexpectedly: {error}. "
                f"Scan results were saved to {ocsf_output.file_path}"
            )
        else:
            job_id = response.get("data", {}).get("id") if response else None
            if job_id:
                print(
                    f"{Style.BRIGHT}{Fore.GREEN}\nOCSF export accepted. Ingestion job: {job_id}{Style.RESET_ALL}"
                )
            else:
                logger.warning(
                    "OCSF export: unexpected API response (missing ingestion job ID). "
                    f"Scan results were saved to {ocsf_output.file_path}"
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
                    file_path=filename,
                )
                generated_outputs["compliance"].append(kisa_ismsp)
                kisa_ismsp.batch_write_data_to_file()
            elif compliance_name == "prowler_threatscore_aws":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                prowler_threatscore = ProwlerThreatScoreAWS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(prowler_threatscore)
                prowler_threatscore.batch_write_data_to_file()
            elif compliance_name.startswith("ccc_"):
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )

                ccc_aws = CCC_AWS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )

                generated_outputs["compliance"].append(ccc_aws)
                ccc_aws.batch_write_data_to_file()
            elif compliance_name == "c5_aws":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                c5 = AWSC5(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(c5)
                c5.batch_write_data_to_file()
            elif compliance_name == "csa_ccm_4.0_aws":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                csa_ccm_4_0_aws = AWSCSA(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(csa_ccm_4_0_aws)
                csa_ccm_4_0_aws.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
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
                    file_path=filename,
                )
                generated_outputs["compliance"].append(ens)
                ens.batch_write_data_to_file()
            elif compliance_name.startswith("iso27001_"):
                # Generate ISO27001 Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                iso27001 = AzureISO27001(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(iso27001)
                iso27001.batch_write_data_to_file()
            elif compliance_name == "prowler_threatscore_azure":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                prowler_threatscore = ProwlerThreatScoreAzure(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(prowler_threatscore)
                prowler_threatscore.batch_write_data_to_file()
            elif compliance_name.startswith("ccc_"):
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                ccc_azure = CCC_Azure(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(ccc_azure)
                ccc_azure.batch_write_data_to_file()
            elif compliance_name == "c5_azure":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                c5_azure = AzureC5(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(c5_azure)
                c5_azure.batch_write_data_to_file()
            elif compliance_name == "csa_ccm_4.0_azure":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                csa_ccm_4_0_azure = AzureCSA(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(csa_ccm_4_0_azure)
                csa_ccm_4_0_azure.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
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
                    file_path=filename,
                )
                generated_outputs["compliance"].append(ens)
                ens.batch_write_data_to_file()
            elif compliance_name.startswith("iso27001_"):
                # Generate ISO27001 Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                iso27001 = GCPISO27001(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(iso27001)
                iso27001.batch_write_data_to_file()
            elif compliance_name == "prowler_threatscore_gcp":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                prowler_threatscore = ProwlerThreatScoreGCP(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(prowler_threatscore)
                prowler_threatscore.batch_write_data_to_file()
            elif compliance_name.startswith("ccc_"):
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                ccc_gcp = CCC_GCP(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(ccc_gcp)
                ccc_gcp.batch_write_data_to_file()
            elif compliance_name == "c5_gcp":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                c5_gcp = GCPC5(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(c5_gcp)
                c5_gcp.batch_write_data_to_file()
            elif compliance_name == "csa_ccm_4.0_gcp":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                csa_ccm_4_0_gcp = GCPCSA(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(csa_ccm_4_0_gcp)
                csa_ccm_4_0_gcp.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
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
                    file_path=filename,
                )
                generated_outputs["compliance"].append(cis)
                cis.batch_write_data_to_file()
            elif compliance_name.startswith("iso27001_"):
                # Generate ISO27001 Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                iso27001 = KubernetesISO27001(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(iso27001)
                iso27001.batch_write_data_to_file()
            elif compliance_name == "prowler_threatscore_kubernetes":
                # Generate Prowler ThreatScore Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                prowler_threatscore = ProwlerThreatScoreKubernetes(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(prowler_threatscore)
                prowler_threatscore.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(generic_compliance)
                generic_compliance.batch_write_data_to_file()

    elif provider == "m365":
        for compliance_name in input_compliance_frameworks:
            if compliance_name.startswith("cis_"):
                # Generate CIS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                cis = M365CIS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(cis)
                cis.batch_write_data_to_file()
            elif compliance_name == "prowler_threatscore_m365":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                prowler_threatscore = ProwlerThreatScoreM365(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(prowler_threatscore)
                prowler_threatscore.batch_write_data_to_file()
            elif compliance_name.startswith("iso27001_"):
                # Generate ISO27001 Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                iso27001 = M365ISO27001(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(iso27001)
                iso27001.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(generic_compliance)
                generic_compliance.batch_write_data_to_file()

    elif provider == "nhn":
        for compliance_name in input_compliance_frameworks:
            if compliance_name.startswith("iso27001_"):
                # Generate ISO27001 Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                iso27001 = NHNISO27001(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(iso27001)
                iso27001.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(generic_compliance)
                generic_compliance.batch_write_data_to_file()

    elif provider == "github":
        for compliance_name in input_compliance_frameworks:
            if compliance_name.startswith("cis_"):
                # Generate CIS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                cis = GithubCIS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
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

    elif provider == "oraclecloud":
        for compliance_name in input_compliance_frameworks:
            if compliance_name.startswith("cis_"):
                # Generate CIS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                cis = OracleCloudCIS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(cis)
                cis.batch_write_data_to_file()
            elif compliance_name == "csa_ccm_4.0_oraclecloud":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                csa_ccm_4_0_oraclecloud = OracleCloudCSA(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(csa_ccm_4_0_oraclecloud)
                csa_ccm_4_0_oraclecloud.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(generic_compliance)
                generic_compliance.batch_write_data_to_file()

    elif provider == "alibabacloud":
        for compliance_name in input_compliance_frameworks:
            if compliance_name.startswith("cis_"):
                # Generate CIS Finding Object
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                cis = AlibabaCloudCIS(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(cis)
                cis.batch_write_data_to_file()
            elif compliance_name == "csa_ccm_4.0_alibabacloud":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                csa_ccm_4_0_alibabacloud = AlibabaCloudCSA(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(csa_ccm_4_0_alibabacloud)
                csa_ccm_4_0_alibabacloud.batch_write_data_to_file()
            elif compliance_name == "prowler_threatscore_alibabacloud":
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                prowler_threatscore = ProwlerThreatScoreAlibaba(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
                    file_path=filename,
                )
                generated_outputs["compliance"].append(prowler_threatscore)
                prowler_threatscore.batch_write_data_to_file()
            else:
                filename = (
                    f"{output_options.output_directory}/compliance/"
                    f"{output_options.output_filename}_{compliance_name}.csv"
                )
                generic_compliance = GenericCompliance(
                    findings=finding_outputs,
                    compliance=bulk_compliance_frameworks[compliance_name],
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
            if findings_sent_to_security_hub == 0:
                print(
                    f"{Style.BRIGHT}{orange_color}\nNo findings sent to AWS Security Hub.{Style.RESET_ALL}"
                )
            else:
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
                if findings_archived_in_security_hub == 0:
                    print(
                        f"{Style.BRIGHT}{orange_color}\nNo findings archived in AWS Security Hub.{Style.RESET_ALL}"
                    )
                else:
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
