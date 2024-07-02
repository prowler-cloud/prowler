import html
import importlib
import sys
from os import path

from prowler.config.config import (
    enconding_format_utf_8,
    html_file_suffix,
    html_logo_url,
    prowler_version,
    square_logo_img,
    timestamp,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.common_models import FindingOutput
from prowler.lib.outputs.utils import parse_html_string, unroll_dict
from prowler.lib.utils.utils import open_file


def add_html_header(file_descriptor, provider):
    try:
        file_descriptor.write(
            f"""
        <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <!-- Required meta tags -->
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <style>
        .read-more {{color: #00f;}}

        .bg-success-custom {{background-color: #98dea7 !important;}}

        .bg-danger {{background-color: #f28484 !important;}}
    </style>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css"
        integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk" crossorigin="anonymous" />
    <!-- https://datatables.net/download/index with jQuery, DataTables, Buttons, SearchPanes, and Select //-->
    <link rel="stylesheet" type="text/css"
        href="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.4.0/sl-1.3.3/datatables.min.css" />
    <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.10.0/css/all.css"
        integrity="sha384-AYmEC3Yw5cVb3ZcuHtOA93w35dYTsvhLPVnYs9eStHfGJvOvKxVfELGroGkvsg+p" crossorigin="anonymous" />
    <style>
        .show-read-more .more-text {{display: none;}}

        .dataTable {{font-size: 14px;}}

        .container-fluid {{font-size: 14px;}}

        .float-left {{ float: left !important; max-width: 100%; }}
    </style>
    <title>Prowler - The Handy Cloud Security Tool</title>
    </head>
    <body>
    <div class="container-fluid">
        <div class="row mt-3">
        <div class="col-md-4">
            <a href="{html_logo_url}"><img class="float-left card-img-left mt-4 mr-4 ml-4"
                        src={square_logo_img}
                        alt="prowler-logo"
                        style="width: 15rem; height:auto;"/></a>
            <div class="card">
            <div class="card-header">
                Report Information
            </div>
            <ul class="list-group list-group-flush">
                <li class="list-group-item">
                <div class="row">
                    <div class="col-md-auto">
                    <b>Version:</b> {prowler_version}
                    </div>
                </div>
                </li>
                <li class="list-group-item">
                <b>Parameters used:</b> {" ".join(sys.argv[1:])}
                </li>
                <li class="list-group-item">
                <b>Date:</b> {timestamp.isoformat()}
                </li>
            </ul>
            </div>
        </div> {get_assessment_summary(provider)}
            <div class="col-md-2">
            <div class="card">
                <div class="card-header">
                    Assessment Overview
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item">
                        <b>Total Findings:</b> TOTAL_FINDINGS
                    </li>
                    <li class="list-group-item">
                        <b>Passed:</b> TOTAL_PASS
                    </li>
                    <li class="list-group-item">
                        <b>Failed:</b> TOTAL_FAIL
                    </li>
                    <li class="list-group-item">
                        <b>Total Resources:</b> TOTAL_RESOURCES
                    </li>
                </ul>
            </div>
        </div>
        </div>
        </div>
        <div class="row-mt-3">
        <div class="col-md-12">
            <table class="table compact stripe row-border ordering" id="findingsTable" data-order='[[ 5, "asc" ]]' data-page-length='100'>
            <thead class="thead-light">
                <tr>
                    <th scope="col">Status</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Service Name</th>
                    <th scope="col">Region</th>
                    <th style="width:20%" scope="col">Check ID</th>
                    <th style="width:20%" scope="col">Check Title</th>
                    <th scope="col">Resource ID</th>
                    <th scope="col">Resource Tags</th>
                    <th scope="col">Status Extended</th>
                    <th scope="col">Risk</th>
                    <th scope="col">Recomendation</th>
                    <th scope="col">Compliance</th>
                </tr>
            </thead>
            <tbody>
    """
        )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)


def fill_html(file_descriptor, finding: FindingOutput):
    try:
        row_class = "p-3 mb-2 bg-success-custom"
        finding_status = finding.status.value
        # Change the status of the finding if it's muted
        if finding.muted:
            finding_status = f"MUTED ({finding_status})"
            row_class = "table-warning"
        if finding.status == "MANUAL":
            row_class = "table-info"
        elif finding.status == "FAIL":
            row_class = "table-danger"

        file_descriptor.write(
            f"""
                <tr class="{row_class}">
                    <td>{finding_status}</td>
                    <td>{finding.severity.value}</td>
                    <td>{finding.service_name}</td>
                    <td>{finding.region.lower()}</td>
                    <td>{finding.check_id.replace("_", "<wbr />_")}</td>
                    <td>{finding.check_title}</td>
                    <td>{finding.resource_uid.replace("<", "&lt;").replace(">", "&gt;").replace("_", "<wbr />_")}</td>
                    <td>{parse_html_string(finding.resource_tags)}</td>
                    <td>{finding.status_extended.replace("<", "&lt;").replace(">", "&gt;").replace("_", "<wbr />_")}</td>
                    <td><p class="show-read-more">{html.escape(finding.risk)}</p></td>
                    <td><p class="show-read-more">{html.escape(finding.remediation_recommendation_text)}</p> <a class="read-more" href="{finding.remediation_recommendation_url}"><i class="fas fa-external-link-alt"></i></a></td>
                    <td><p class="show-read-more">{parse_html_string(unroll_dict(finding.compliance))}</p></td>
                </tr>
                """
        )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)


def fill_html_overview_statistics(stats, output_filename, output_directory):
    try:
        filename = f"{output_directory}/{output_filename}{html_file_suffix}"

        # Read file
        if path.isfile(filename):
            with open(filename, "r", encoding=enconding_format_utf_8) as file:
                filedata = file.read()

            # Replace statistics
            # TOTAL_FINDINGS
            filedata = filedata.replace(
                "TOTAL_FINDINGS", str(stats.get("findings_count", 0))
            )
            # TOTAL_RESOURCES
            filedata = filedata.replace(
                "TOTAL_RESOURCES", str(stats.get("resources_count", 0))
            )
            # TOTAL_PASS
            filedata = filedata.replace("TOTAL_PASS", str(stats.get("total_pass", 0)))
            # TOTAL_FAIL
            filedata = filedata.replace("TOTAL_FAIL", str(stats.get("total_fail", 0)))

            # Write file
            with open(filename, "w", encoding=enconding_format_utf_8) as file:
                file.write(filedata)

    except FileNotFoundError as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
    except UnicodeDecodeError as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )


def add_html_footer(output_filename, output_directory):
    try:
        filename = f"{output_directory}/{output_filename}{html_file_suffix}"
        # Close HTML file if exists
        if path.isfile(filename):
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
    <!-- Table search and paginator -->
    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"
        integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.bundle.min.js"
        integrity="sha384-1CmrxMRARb6aLqgBO7yyAxTOQE2AKb9GfXnEo760AUcUmFx3ibVJJAzGytlQcNXd"
        crossorigin="anonymous"></script>
    <!-- https://datatables.net/download/index with jQuery, DataTables, Buttons, SearchPanes, and Select //-->
    <script type="text/javascript"
        src="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.4.0/sl-1.3.3/datatables.min.js"></script>
    <script>
        $(document).ready(function () {
            // Initialise the table with 50 rows, and some search/filtering panes
            $('#findingsTable').DataTable({
                responsive: true,
                // Show 25, 50, 100 and All records
                lengthChange: true,
                lengthMenu: [[25, 50, 100, -1], [25, 50, 100, "All"]],
                searchPanes: {
                    cascadePanes: true,
                    viewTotal: true,
                },
                dom: 'Blfrtip',
                language: {
                    // To enable a filter button instead of the filter row
                    searchPanes: {
                        clearMessage: 'Clear Filters',
                        collapse: { 0: 'Filters', _: 'Filters (%d)' },
                        initCollapsed: true

                    }
                },
                buttons: [
                    {
                        extend: 'searchPanes',
                        config: {
                            cascadePanes: true,
                            viewTotal: true,
                            orderable: false
                        }
                    }
                ],
                columnDefs: [
                    {
                        searchPanes: {
                            show: true,
                            pagingType: 'numbers',
                            searching: true
                        },
                        // Show all filters
                        targets: [0, 1, 2, 3, 5, 7]
                    }
                ]
            });
            var maxLength = 30;
            // ReadMore ReadLess
            $(".show-read-more").each(function () {
                var myStr = $(this).text();
                if ($.trim(myStr).length > maxLength) {
                    var newStr = myStr.substring(0, maxLength);
                    var removedStr = myStr.substring(maxLength, $.trim(myStr).length);
                    $(this).empty().html(newStr);
                    $(this).append(' <a href="javascript:void(0);" class="read-more">read more...</a>');
                    $(this).append('<span class="more-text">' + removedStr + '</span>');
                }
            });
            $(".read-more").click(function () {
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
        sys.exit(1)


def get_aws_html_assessment_summary(provider):
    try:
        if provider.__class__.__name__ == "AwsProvider":
            profile = (
                provider._identity.profile
                if provider._identity.profile is not None
                else "default"
            )
            if isinstance(provider._identity.audited_regions, list):
                audited_regions = " ".join(provider._identity.audited_regions)
            elif not provider._identity.audited_regions:
                audited_regions = "All Regions"
            else:
                audited_regions = ", ".join(provider._identity.audited_regions)
            return f"""
            <div class="col-md-2">
                <div class="card">
                    <div class="card-header">
                        AWS Assessment Summary
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>AWS Account:</b> {provider._identity.account}
                        </li>
                        <li class="list-group-item">
                            <b>AWS-CLI Profile:</b> {profile}
                        </li>
                        <li class="list-group-item">
                            <b>Audited Regions:</b> {audited_regions}
                        </li>
                    </ul>
                </div>
            </div>
            <div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    AWS Credentials
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item">
                        <b>User Id:</b> {provider._identity.user_id}
                        </li>
                        <li class="list-group-item">
                            <b>Caller Identity ARN:</b> {provider._identity.identity_arn}
                        </li>
                    </ul>
                </div>
            </div>
            """

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)


def get_azure_html_assessment_summary(provider):
    try:
        if provider.__class__.__name__ == "AzureProvider":
            printed_subscriptions = []
            for key, value in provider._identity.subscriptions.items():
                intermediate = f"{key} : {value}"
                printed_subscriptions.append(intermediate)

            # check if identity is str(coming from SP) or dict(coming from browser or)
            if isinstance(provider._identity.identity_id, dict):
                html_identity = provider._identity.identity_id.get(
                    "userPrincipalName", "Identity not found"
                )
            else:
                html_identity = provider._identity.identity_id
            return f"""
            <div class="col-md-2">
                <div class="card">
                    <div class="card-header">
                        Azure Assessment Summary
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>Azure Tenant IDs:</b> {" ".join(provider._identity.tenant_ids)}
                        </li>
                        <li class="list-group-item">
                            <b>Azure Tenant Domain:</b> {provider._identity.tenant_domain}
                        </li>
                        <li class="list-group-item">
                            <b>Azure Subscriptions:</b> {" ".join(printed_subscriptions)}
                        </li>
                    </ul>
                </div>
            </div>
            <div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    Azure Credentials
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item">
                        <b>Azure Identity Type:</b> {provider._identity.identity_type}
                        </li>
                        <li class="list-group-item">
                            <b>Azure Identity ID:</b> {html_identity}
                        </li>
                    </ul>
                </div>
            </div>
            """
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)


def get_gcp_html_assessment_summary(provider):
    try:
        if provider.__class__.__name__ == "GcpProvider":
            try:
                getattr(provider.credentials, "_service_account_email")
                profile = (
                    provider.credentials._service_account_email
                    if provider.credentials._service_account_email is not None
                    else "default"
                )
            except AttributeError:
                profile = "default"
            return f"""
            <div class="col-md-2">
                <div class="card">
                    <div class="card-header">
                        GCP Assessment Summary
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>GCP Project IDs:</b> {", ".join(provider.project_ids)}
                        </li>
                    </ul>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        GCP Credentials
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>GCP Account:</b> {profile}
                        </li>
                    </ul>
                </div>
            </div>
            """
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)


def get_kubernetes_html_assessment_summary(provider):
    try:
        if provider.__class__.__name__ == "KubernetesProvider":
            return f"""
            <div class="col-md-2">
                <div class="card">
                    <div class="card-header">
                        Kubernetes Assessment Summary
                    </div>
                    <ul class="list-group
                    list-group-flush">
                        <li class="list-group-item">
                            <b>Kubernetes Cluster:</b> {provider._identity.cluster}
                        </li>
                    </ul>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        Kubernetes Credentials
                    </div>
                    <ul class="list-group
                    list-group-flush">
                        <li class="list-group-item">
                            <b>Kubernetes Context:</b> {provider._identity.context}
                        </li>
                    </ul>
                </div>
            </div>
            """
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit(1)


def get_assessment_summary(provider):
    """
    get_assessment_summary gets the HTML assessment summary for the provider
    """
    try:
        # This is based in the Provider_provider class
        # It is not pretty but useful
        # AWS_provider --> aws
        # GCP_provider --> gcp
        # Azure_provider --> azure

        # Dynamically get the Provider quick inventory handler
        provider_html_assessment_summary_function = (
            f"get_{provider.type}_html_assessment_summary"
        )
        return getattr(
            importlib.import_module(__name__), provider_html_assessment_summary_function
        )(provider)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)
