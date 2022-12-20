import sys

from prowler.config.config import (
    html_file_suffix,
    html_logo_img,
    html_logo_url,
    prowler_version,
    timestamp,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file


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
        .read-more {
            color: #00f;
        }

        .bg-success-custom {
            background-color: #98dea7 !important;
        }

        .bg-danger {
            background-color: #f28484 !important;
        }
    </style>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css"
        integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk" crossorigin="anonymous">
    <!-- https://datatables.net/download/index with jQuery, DataTables, Buttons, SearchPanes, and Select //-->
    <link rel="stylesheet" type="text/css"
        href="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.4.0/sl-1.3.3/datatables.min.css" />
    <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.10.0/css/all.css"
        integrity="sha384-AYmEC3Yw5cVb3ZcuHtOA93w35dYTsvhLPVnYs9eStHfGJvOvKxVfELGroGkvsg+p" crossorigin="anonymous" />
    <style>
        .show-read-more .more-text {
            display: none;
        }

        .dataTable {
            font-size: 14px;
        }

        .container-fluid {
            font-size: 14px;
        }

        .float-left {
            float: left !important;
            max-width: 100%;
        }
    </style>
    <title>Prowler - The Handy Cloud Security Tool</title>
    </head>
    <body>
    <div class="container-fluid">
        <div class="row mt-3">
        <div class="col-md-4">
            <a href="""
            + html_logo_url
            + """><img class="float-left card-img-left mt-4 mr-4 ml-4"
                        src="""
            + html_logo_img
            + """
                        alt="prowler-logo"></a>
            <div class="card">
            <div class="card-header">
                Report Information
            </div>
            <ul class="list-group list-group-flush">
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
        <div class="col-md-2">
                <div class="card">
                    <div class="card-header">
                        AWS Assessment Summary
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
                            <b>User Id:</b> """
            + audit_info.audited_user_id
            + """
                        </li>
                        <li class="list-group-item">
                            <b>Caller Identity ARN:</b>
                            """
            + audit_info.audited_identity_arn
            + """
                        </li>
                    </ul>
                </div>
            </div>
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
                    <th style="width:5%" scope="col">Service Name</th>
                    <th scope="col">Region</th>
                    <th style="width:20%" scope="col">Check Title</th>
                    <th scope="col">Resource ID</th>
                    <th style="width:15%" scope="col">Check Description</th>
                    <th scope="col">Check ID</th>
                    <th scope="col">Status Extended</th>
                    <th scope="col">Risk</th>
                    <th scope="col">Recomendation</th>
                    <th style="width:5%" scope="col">Recomendation URL</th>
                </tr>
            </thead>
            <tbody>
    """
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def fill_html(file_descriptor, finding):
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
                <td>{finding.resource_id.replace("<", "&lt;").replace(">", "&gt;").replace("_", "<wbr>_")}</td>
                <td>{finding.check_metadata.Description}</td>
                <td>{finding.check_metadata.CheckID.replace("_", "<wbr>_")}</td>
                <td>{finding.status_extended.replace("<", "&lt;").replace(">", "&gt;").replace("_", "<wbr>_")}</td>
                <td><p class="show-read-more">{finding.check_metadata.Risk}</p></td>
                <td><p class="show-read-more">{finding.check_metadata.Remediation.Recommendation.Text}</p></td>
                <td><a class="read-more" href="{finding.check_metadata.Remediation.Recommendation.Url}"><i class="fas fa-external-link-alt"></i></a></td>
            </tr>
            """
    )


def fill_html_overview_statistics(stats, output_filename, output_directory):
    try:
        filename = f"{output_directory}/{output_filename}{html_file_suffix}"
        #  Read file
        with open(filename, "r") as file:
            filedata = file.read()

        # Replace statistics
        # TOTAL_FINDINGS
        filedata = filedata.replace("TOTAL_FINDINGS", str(stats.get("findings_count")))
        # TOTAL_RESOURCES
        filedata = filedata.replace(
            "TOTAL_RESOURCES", str(stats.get("resources_count"))
        )
        # TOTAL_PASS
        filedata = filedata.replace("TOTAL_PASS", str(stats.get("total_pass")))
        # TOTAL_FAIL
        filedata = filedata.replace("TOTAL_FAIL", str(stats.get("total_fail")))
        # Write file
        with open(filename, "w") as file:
            file.write(filedata)

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit()


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
        sys.exit()
