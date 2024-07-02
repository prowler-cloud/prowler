from datetime import datetime
from io import StringIO

import pytest

from prowler.config.config import timestamp
from prowler.lib.outputs.finding import Finding, Severity, Status
from prowler.lib.outputs.html.html import HTML
from tests.providers.aws.utils import set_mocked_aws_provider

html_stats = {
    "total_pass": 0,
    "total_fail": 1,
    "resources_count": 1,
    "findings_count": 1,
}

html_finding = """
                        <tr class="table-danger">
                            <td>FAIL</td>
                            <td>critical</td>
                            <td>Example Service</td>
                            <td>us-west-1</td>
                            <td>check-123</td>
                            <td>Example Check</td>
                            <td>resource-123</td>
                            <td>
&#x2022;tag1,tag2
</td>
                            <td>Extended status</td>
                            <td><p class="show-read-more">High</p></td>
                            <td><p class="show-read-more">Recommendation text</p> <a class="read-more" href="http://example.com/remediation"><i class="fas fa-external-link-alt"></i></a></td>
                            <td><p class="show-read-more">
&#x2022;compliance_key: compliance_value
</p></td>
                        </tr>
                        """

html_header = (
    """
<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <!-- Required meta tags -->
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <style>
        .read-more {color: #00f;}

        .bg-success-custom {background-color: #98dea7 !important;}

        .bg-danger {background-color: #f28484 !important;}
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
        .show-read-more .more-text {display: none;}

        .dataTable {font-size: 14px;}

        .container-fluid {font-size: 14px;}

        .float-left { float: left !important; max-width: 100%; }
    </style>
    <title>Prowler - The Handy Cloud Security Tool</title>
    </head>
    <body>
    <div class="container-fluid">
        <div class="row mt-3">
        <div class="col-md-4">
            <a href="https://github.com/prowler-cloud/prowler/"><img class="float-left card-img-left mt-4 mr-4 ml-4"
                        src=https://prowler.com/wp-content/uploads/logo-html.png
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
                    <b>Version:</b> 4.2.4
                    </div>
                </div>
                </li>
                <li class="list-group-item">
                <b>Parameters used:</b> tests/lib/outputs/ -vv
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
                                <b>AWS Account:</b> 123456789012
                            </li>
                            <li class="list-group-item">
                                <b>AWS-CLI Profile:</b> default
                            </li>
                            <li class="list-group-item">
                                <b>Audited Regions:</b>
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
                            <b>User Id:</b> None
                            </li>
                            <li class="list-group-item">
                                <b>Caller Identity ARN:</b> None
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
                        <b>Total Findings:</b> 1
                    </li>
                    <li class="list-group-item">
                        <b>Passed:</b> 0
                    </li>
                    <li class="list-group-item">
                        <b>Failed:</b> 1
                    </li>
                    <li class="list-group-item">
                        <b>Total Resources:</b> 1
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
            <tbody>"""
)

html_footer = """
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


@pytest.fixture
def generate_finding():
    return Finding(
        auth_method="OAuth",
        timestamp=datetime.now(),
        account_uid="12345",
        account_name="Example Account",
        account_email="example@example.com",
        account_organization_uid="org-123",
        account_organization_name="Example Org",
        account_tags=["tag1", "tag2"],
        finding_uid="finding-123",
        provider="aws",
        check_id="check-123",
        check_title="Example Check",
        check_type="Security",
        status=Status("FAIL"),
        status_extended="Extended status",
        muted=False,
        service_name="Example Service",
        subservice_name="Example Subservice",
        severity=Severity("critical"),
        resource_type="Instance",
        resource_uid="resource-123",
        resource_name="Example Resource",
        resource_details="Detailed information about the resource",
        resource_tags="tag1,tag2",
        partition="aws",
        region="us-west-1",
        description="Description of the finding",
        risk="High",
        related_url="http://example.com",
        remediation_recommendation_text="Recommendation text",
        remediation_recommendation_url="http://example.com/remediation",
        remediation_code_nativeiac="native-iac-code",
        remediation_code_terraform="terraform-code",
        remediation_code_cli="cli-code",
        remediation_code_other="other-code",
        compliance={"compliance_key": "compliance_value"},
        categories="category1,category2",
        depends_on="dependency",
        related_to="related finding",
        notes="Notes about the finding",
        prowler_version="1.0",
    )


class TestHTML:
    def test_transform(self, generate_finding):
        findings = [generate_finding]

        # Clear the data from CSV class
        HTML._data = []

        html = HTML(findings)
        output_data = html.data[0]
        assert isinstance(output_data, str)
        assert output_data == html_finding

    def test_batch_write_data_to_file(self, generate_finding):
        mock_file = StringIO()
        findings = [generate_finding]
        # Clear the data from CSV class
        HTML._data = []
        output = HTML(findings)
        output._file_descriptor = mock_file

        # FIXME: This function need the Check_Report_XXX findings
        # stats = extract_findings_statistics(findings)
        provider = set_mocked_aws_provider()

        output.batch_write_data_to_file(provider, html_stats)

        mock_file.seek(0)
        content = mock_file.read()
        assert content == html_header + html_finding + html_footer

    def test_write_header(self, generate_finding):
        mock_file = StringIO()
        findings = [generate_finding]
        # Clear the data from CSV class
        HTML._data = []
        output = HTML(findings)
        output._file_descriptor = mock_file
        provider = set_mocked_aws_provider()

        output.write_header(mock_file, provider, html_stats)

        mock_file.seek(0)
        content = mock_file.read()
        assert content == html_header

    def test_write_footer(self, generate_finding):
        mock_file = StringIO()
        findings = [generate_finding]
        # Clear the data from CSV class
        HTML._data = []
        output = HTML(findings)
        output._file_descriptor = mock_file

        output.write_footer(mock_file)

        mock_file.seek(0)
        content = mock_file.read()
        assert content == html_footer
