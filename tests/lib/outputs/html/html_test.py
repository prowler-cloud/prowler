import sys
from io import StringIO

from mock import patch

from prowler.config.config import prowler_version, timestamp
from prowler.lib.outputs.html.html import HTML
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider
from tests.providers.azure.azure_fixtures import set_mocked_azure_provider
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)

html_stats = {
    "total_pass": 25,
    "total_muted_pass": 20,
    "total_fail": 5,
    "total_muted_fail": 5,
    "resources_count": 1,
    "findings_count": 30,
}
pass_html_finding = """
                        <tr class="p-3 mb-2 bg-success-custom">
                            <td>PASS</td>
                            <td>high</td>
                            <td>test-service</td>
                            <td>eu-west-1</td>
                            <td>test-check-id</td>
                            <td>test-check-id</td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td><p class="show-read-more">test-risk</p></td>
                            <td><p class="show-read-more"></p> <a class="read-more" href=""><i class="fas fa-external-link-alt"></i></a></td>
                            <td><p class="show-read-more">
&#x2022;test-compliance: test-compliance
</p></td>
                        </tr>
                        """
fail_html_finding = """
                        <tr class="table-danger">
                            <td>FAIL</td>
                            <td>high</td>
                            <td>test-service</td>
                            <td>eu-west-1</td>
                            <td>test-check-id</td>
                            <td>test-check-id</td>
                            <td>test-resource-uid</td>
                            <td>
&#x2022;key1=value1

&#x2022;key2=value2
</td>
                            <td>test-status-extended</td>
                            <td><p class="show-read-more">test-risk</p></td>
                            <td><p class="show-read-more">test-remediation-recommendation-text</p> <a class="read-more" href=""><i class="fas fa-external-link-alt"></i></a></td>
                            <td><p class="show-read-more">
&#x2022;test-compliance: test-compliance
</p></td>
                        </tr>
                        """
muted_html_finding = """
                        <tr class="table-warning">
                            <td>MUTED (PASS)</td>
                            <td>high</td>
                            <td>test-service</td>
                            <td>eu-west-1</td>
                            <td>test-check-id</td>
                            <td>test-check-id</td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td><p class="show-read-more">test-risk</p></td>
                            <td><p class="show-read-more"></p> <a class="read-more" href=""><i class="fas fa-external-link-alt"></i></a></td>
                            <td><p class="show-read-more">
&#x2022;test-compliance: test-compliance
</p></td>
                        </tr>
                        """
manual_html_finding = """
                        <tr class="table-info">
                            <td>MANUAL</td>
                            <td>high</td>
                            <td>test-service</td>
                            <td>eu-west-1</td>
                            <td>test-check-id</td>
                            <td>test-check-id</td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td><p class="show-read-more">test-risk</p></td>
                            <td><p class="show-read-more"></p> <a class="read-more" href=""><i class="fas fa-external-link-alt"></i></a></td>
                            <td><p class="show-read-more">
&#x2022;test-compliance: test-compliance
</p></td>
                        </tr>
                        """
aws_html_assessment_summary = """
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
                                <b>Audited Regions:</b> eu-west-1
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
                </div>"""

azure_html_assessment_summary = """

                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Azure Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>Azure Tenant IDs:</b> 00000000-0000-0000-0000-000000000000
                            </li>
                            <li class="list-group-item">
                                <b>Azure Tenant Domain:</b> Unknown tenant domain (missing AAD permissions)
                            </li>
                            <li class="list-group-item">
                                <b>Azure Subscriptions:</b> 4f647f43-15d2-4e3a-a7f0-8517cc4d977b : Subscription Name
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
                            <b>Azure Identity Type:</b> Service Principal
                            </li>
                            <li class="list-group-item">
                                <b>Azure Identity ID:</b> 00000000-0000-0000-0000-000000000000
                            </li>
                        </ul>
                    </div>
                </div>"""

gcp_html_assessment_summary = """
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            GCP Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>GCP Project IDs:</b> 123456789012
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
                                <b>GCP Account:</b> test@test.com
                            </li>
                        </ul>
                    </div>
                </div>"""

kubernetes_html_assessment_summary = """
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Kubernetes Assessment Summary
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>Kubernetes Cluster:</b> None
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
                                <b>Kubernetes Context:</b> None
                            </li>
                        </ul>
                    </div>
                </div>"""


def get_aws_html_header(args: list) -> str:
    """
    Generate the HTML header for AWS

    Args:
        args (list): List of arguments passed to the script

    Returns:
        str: HTML header for AWS
    """
    aws_html_header = f"""
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
                    <b>Version:</b> {prowler_version}
                    </div>
                </div>
                </li>
                <li class="list-group-item">
                <b>Parameters used:</b> {" ".join(args)}
                </li>
                <li class="list-group-item">
                <b>Date:</b> {timestamp.isoformat()}
                </li>
            </ul>
            </div>
        </div>{aws_html_assessment_summary}
            <div class="col-md-2">
            <div class="card">
                <div class="card-header">
                    Assessment Overview
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item">
                        <b>Total Findings:</b> 30
                    </li>
                    <li class="list-group-item">
                        <b>Passed:</b> 25
                    </li>
                    <li class="list-group-item">
                        <b>Passed (Muted):</b> 20
                    </li>
                    <li class="list-group-item">
                        <b>Failed:</b> 5
                    </li>
                    <li class="list-group-item">
                        <b>Failed (Muted):</b> 5
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
    return aws_html_header


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


class TestHTML:
    def test_transform_fail_finding(self):
        findings = [
            generate_finding_output(
                status="FAIL",
                resource_tags={"key1": "value1", "key2": "value2"},
                severity="high",
                service_name="test-service",
                region=AWS_REGION_EU_WEST_1,
                check_id="test-check-id",
                check_title="test-check-id",
                resource_uid="test-resource-uid",
                status_extended="test-status-extended",
                risk="test-risk",
                remediation_recommendation_text="test-remediation-recommendation-text",
                compliance={"test-compliance": "test-compliance"},
            )
        ]

        html = HTML(findings)
        output_data = html.data[0]
        assert isinstance(output_data, str)
        assert output_data == fail_html_finding

    def test_transform_pass_finding(self):
        findings = [generate_finding_output()]
        html = HTML(findings)
        output_data = html.data[0]
        assert isinstance(output_data, str)
        assert output_data == pass_html_finding

    def test_transform_muted_finding(self):
        findings = [generate_finding_output(muted=True)]
        html = HTML(findings)
        output_data = html.data[0]
        assert isinstance(output_data, str)
        assert output_data == muted_html_finding

    def test_transform_manual_finding(self):
        findings = [generate_finding_output(status="MANUAL")]
        html = HTML(findings)
        output_data = html.data[0]
        assert isinstance(output_data, str)
        assert output_data == manual_html_finding

    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [generate_finding_output()]
        output = HTML(findings)
        output._file_descriptor = mock_file
        provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_EU_WEST_1])

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file(provider, html_stats)

        mock_file.seek(0)
        content = mock_file.read()
        args = sys.argv[1:]
        assert content == get_aws_html_header(args) + pass_html_finding + html_footer

    def test_batch_write_data_to_file_without_findings(self):
        assert not hasattr(HTML([]), "_file_descriptor")

    def test_write_header(self):
        mock_file = StringIO()
        findings = [generate_finding_output()]
        output = HTML(findings)
        output._file_descriptor = mock_file
        provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_EU_WEST_1])

        output.write_header(mock_file, provider, html_stats)

        mock_file.seek(0)
        content = mock_file.read()
        args = sys.argv[1:]
        assert content == get_aws_html_header(args)

    def test_write_footer(self):
        mock_file = StringIO()
        findings = [generate_finding_output()]
        output = HTML(findings)
        output._file_descriptor = mock_file

        output.write_footer(mock_file)

        mock_file.seek(0)
        content = mock_file.read()
        assert content == html_footer

    def test_aws_get_assessment_summary(self):
        findings = [generate_finding_output()]
        output = HTML(findings)
        provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_EU_WEST_1])

        summary = output.get_assessment_summary(provider)

        assert summary == aws_html_assessment_summary

    def test_azure_get_assessment_summary(self):
        findings = [generate_finding_output()]
        output = HTML(findings)
        provider = set_mocked_azure_provider()

        summary = output.get_assessment_summary(provider)

        assert summary == summary

    def test_gcp_get_assessment_summary(self):
        findings = [generate_finding_output()]
        output = HTML(findings)
        provider = set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])

        summary = output.get_assessment_summary(provider)

        assert summary == gcp_html_assessment_summary

    def test_kubernetes_get_assessment_summary(self):
        findings = [generate_finding_output()]
        output = HTML(findings)
        provider = set_mocked_kubernetes_provider()

        summary = output.get_assessment_summary(provider)

        assert summary == kubernetes_html_assessment_summary
