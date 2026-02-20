import sys
from io import StringIO

from mock import MagicMock, patch

from prowler.config.config import prowler_version, timestamp
from prowler.lib.logger import logger
from prowler.lib.outputs.html.html import HTML
from prowler.providers.github.models import GithubAppIdentityInfo
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider
from tests.providers.azure.azure_fixtures import set_mocked_azure_provider
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider
from tests.providers.github.github_fixtures import APP_ID, set_mocked_github_provider
from tests.providers.kubernetes.kubernetes_fixtures import (
    set_mocked_kubernetes_provider,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    set_mocked_mongodbatlas_provider,
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
                            <td>service</td>
                            <td>eu-west-1</td>
                            <td>service<wbr />_test<wbr />_check<wbr />_id</td>
                            <td>service_test_check_id</td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td><p class="show-read-more">test-risk</p></td>
                            <td><p class="show-read-more"></p> <a class="read-more" href="https://hub.prowler.com/check/check-id"><i class="fas fa-external-link-alt"></i></a></td>
                            <td><p class="show-read-more">
&#x2022;test-compliance: test-compliance
</p></td>
                        </tr>
                        """
fail_html_finding = """
                        <tr class="table-danger">
                            <td>FAIL</td>
                            <td>high</td>
                            <td>service</td>
                            <td>eu-west-1</td>
                            <td>service<wbr />_test<wbr />_check<wbr />_id</td>
                            <td>service_test_check_id</td>
                            <td>test-resource-uid</td>
                            <td>
&#x2022;key1=value1

&#x2022;key2=value2
</td>
                            <td>test-status-extended</td>
                            <td><p class="show-read-more">test-risk</p></td>
                            <td><p class="show-read-more">test-remediation-recommendation-text</p> <a class="read-more" href="https://hub.prowler.com/check/check-id"><i class="fas fa-external-link-alt"></i></a></td>
                            <td><p class="show-read-more">
&#x2022;test-compliance: test-compliance
</p></td>
                        </tr>
                        """
muted_html_finding = """
                        <tr class="table-warning">
                            <td>MUTED (PASS)</td>
                            <td>high</td>
                            <td>service</td>
                            <td>eu-west-1</td>
                            <td>service<wbr />_test<wbr />_check<wbr />_id</td>
                            <td>service_test_check_id</td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td><p class="show-read-more">test-risk</p></td>
                            <td><p class="show-read-more"></p> <a class="read-more" href="https://hub.prowler.com/check/check-id"><i class="fas fa-external-link-alt"></i></a></td>
                            <td><p class="show-read-more">
&#x2022;test-compliance: test-compliance
</p></td>
                        </tr>
                        """
manual_html_finding = """
                        <tr class="table-info">
                            <td>MANUAL</td>
                            <td>high</td>
                            <td>service</td>
                            <td>eu-west-1</td>
                            <td>service<wbr />_test<wbr />_check<wbr />_id</td>
                            <td>service_test_check_id</td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td><p class="show-read-more">test-risk</p></td>
                            <td><p class="show-read-more"></p> <a class="read-more" href="https://hub.prowler.com/check/check-id"><i class="fas fa-external-link-alt"></i></a></td>
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

github_personal_access_token_html_assessment_summary = """
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            GitHub Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">

                            <li class="list-group-item">
                                <b>GitHub account:</b> account-name
                            </li>

                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            GitHub Credentials
                        </div>
                        <ul class="list-group list-group-flush">

                            <li class="list-group-item">
                                <b>GitHub authentication method:</b> Personal Access Token
                            </li>
                        </ul>
                    </div>
                </div>"""

github_app_html_assessment_summary = """
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            GitHub Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>GitHub App Name:</b> test-app
                            </li>
                            <li class="list-group-item">
                                <b>Installations:</b> test-org
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            GitHub Credentials
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>GitHub authentication method:</b> GitHub App Token
                            </li>
                            <li class="list-group-item">
                                <b>GitHub App ID:</b> app-id
                            </li>
                        </ul>
                    </div>
                </div>"""

m365_html_assessment_summary = """
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            M365 Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>M365 Tenant Domain:</b> user.onmicrosoft.com
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        M365 Credentials
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>M365 Identity Type:</b> Application
                            </li>
                            <li class="list-group-item">
                                <b>M365 Identity ID:</b> 00000000-0000-0000-0000-000000000000
                            </li>
                            <li class="list-group-item">
                                <b>M365 User:</b> user@email.com
                            </li>
                        </ul>
                    </div>
                </div>"""

mongodbatlas_html_assessment_summary = """
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            MongoDB Atlas Assessment Summary
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>MongoDB Atlas organization:</b> test_org_name
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            MongoDB Atlas Credentials
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>MongoDB Atlas authentication method:</b> API Key
                            </li>
                        </ul>
                    </div>
                </div>"""

image_registry_html_assessment_summary = """
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Image Assessment Summary
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>Registry URL:</b> myregistry.io
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            Image Credentials
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>Image authentication method:</b> Docker login
                            </li>
                        </ul>
                    </div>
                </div>"""

image_list_html_assessment_summary = """
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Image Assessment Summary
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>Images:</b> nginx:latest, alpine:3.18
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            Image Credentials
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>Image authentication method:</b> No auth
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
    aws_html_header = f"""<!DOCTYPE html>
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
                        src=https://raw.githubusercontent.com/prowler-cloud/prowler/dc7d2d5aeb92fdf12e8604f42ef6472cd3e8e889/docs/img/prowler-logo-black.png
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
                    <th scope="col">Recommendation</th>
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
                var myStr = $(this).html();
                var textLength = $(this).text().length;
                if (textLength > maxLength) {
                    // Find the position where to cut while preserving HTML tags and breaking at word boundaries
                    var cutPosition = 0;
                    var currentLength = 0;
                    var inTag = false;
                    var lastWordBoundary = 0;
                    var tagStack = [];

                    for (var i = 0; i < myStr.length; i++) {
                        if (myStr[i] === '<') {
                            inTag = true;
                            // Track opening tags
                            if (myStr[i + 1] !== '/') {
                                var tagEnd = myStr.indexOf('>', i);
                                if (tagEnd !== -1) {
                                    var tagName = myStr.substring(i + 1, tagEnd).split(' ')[0];
                                    tagStack.push(tagName);
                                }
                            } else {
                                // Closing tag
                                var tagEnd = myStr.indexOf('>', i);
                                if (tagEnd !== -1) {
                                    var tagName = myStr.substring(i + 2, tagEnd).split(' ')[0];
                                    if (tagStack.length > 0) {
                                        tagStack.pop();
                                    }
                                }
                            }
                        } else if (myStr[i] === '>') {
                            inTag = false;
                        } else if (!inTag) {
                            currentLength++;
                            // Only consider word boundaries if we're not inside any HTML tags
                            if (tagStack.length === 0 && (myStr[i] === ' ' || myStr[i] === '.' || myStr[i] === ',' || myStr[i] === ';' || myStr[i] === ':' || myStr[i] === '!' || myStr[i] === '?')) {
                                lastWordBoundary = i + 1;
                            }

                            if (currentLength >= maxLength) {
                                // If we're inside HTML tags, find the next closing tag
                                if (tagStack.length > 0) {
                                    // Find the next closing tag for the current open tag
                                    var nextClosingTag = '</' + tagStack[tagStack.length - 1] + '>';
                                    var closingTagPos = myStr.indexOf(nextClosingTag, i);
                                    if (closingTagPos !== -1) {
                                        cutPosition = closingTagPos + nextClosingTag.length;
                                    } else {
                                        // If no closing tag found, use current position
                                        cutPosition = i + 1;
                                    }
                                } else {
                                    // Use the last word boundary if available, otherwise use current position
                                    cutPosition = lastWordBoundary > 0 ? lastWordBoundary : i + 1;
                                }
                                break;
                            }
                        }
                    }

                    var newStr = myStr.substring(0, cutPosition);
                    var removedStr = myStr.substring(cutPosition);
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
                service_name="service",
                region=AWS_REGION_EU_WEST_1,
                check_id="service_test_check_id",
                check_title="service_test_check_id",
                resource_uid="test-resource-uid",
                status_extended="test-status-extended",
                risk="test-risk",
                remediation_recommendation_text="test-remediation-recommendation-text",
                remediation_recommendation_url="https://hub.prowler.com/check/check-id",
                compliance={"test-compliance": "test-compliance"},
            )
        ]

        html = HTML(findings)
        output_data = html.data[0]
        assert isinstance(output_data, str)
        assert output_data == fail_html_finding

    def test_transform_pass_finding(self):
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        html = HTML(findings)
        output_data = html.data[0]
        assert isinstance(output_data, str)
        assert output_data == pass_html_finding

    def test_transform_muted_finding(self):
        findings = [
            generate_finding_output(
                muted=True,
                remediation_recommendation_url="https://hub.prowler.com/check/check-id",
            )
        ]
        html = HTML(findings)
        output_data = html.data[0]
        assert isinstance(output_data, str)
        assert output_data == muted_html_finding

    def test_transform_manual_finding(self):
        findings = [
            generate_finding_output(
                status="MANUAL",
                remediation_recommendation_url="https://hub.prowler.com/check/check-id",
            )
        ]
        html = HTML(findings)
        output_data = html.data[0]
        assert isinstance(output_data, str)
        assert output_data == manual_html_finding

    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
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
        assert not HTML([])._file_descriptor

    def test_write_header(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
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
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        output = HTML(findings)
        output._file_descriptor = mock_file

        output.write_footer(mock_file)

        mock_file.seek(0)
        content = mock_file.read()
        assert content == html_footer

    def test_aws_get_assessment_summary(self):
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        output = HTML(findings)
        provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_EU_WEST_1])

        summary = output.get_assessment_summary(provider)

        assert summary == aws_html_assessment_summary

    def test_azure_get_assessment_summary(self):
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        output = HTML(findings)
        provider = set_mocked_azure_provider()

        summary = output.get_assessment_summary(provider)

        assert summary == summary

    def test_gcp_get_assessment_summary(self):
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        output = HTML(findings)
        provider = set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])

        summary = output.get_assessment_summary(provider)

        assert summary == gcp_html_assessment_summary

    def test_kubernetes_get_assessment_summary(self):
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        output = HTML(findings)
        provider = set_mocked_kubernetes_provider()

        summary = output.get_assessment_summary(provider)

        assert summary == kubernetes_html_assessment_summary

    def test_m365_get_assessment_summary(self):
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        output = HTML(findings)
        provider = set_mocked_m365_provider()

        summary = output.get_assessment_summary(provider)

        expected_summary = m365_html_assessment_summary
        assert summary == expected_summary

    def test_github_personal_access_token_get_assessment_summary(self):
        """Test GitHub HTML assessment summary generation with Personal Access Token authentication."""
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        output = HTML(findings)
        provider = set_mocked_github_provider(auth_method="Personal Access Token")

        summary = output.get_assessment_summary(provider)

        # Check for expected content in the summary
        assert "GitHub Assessment Summary" in summary
        assert "GitHub Credentials" in summary
        assert "<b>GitHub account:</b> account-name" in summary
        assert "<b>GitHub authentication method:</b> Personal Access Token" in summary
        # Note: account_email is None in the default fixture, so it shouldn't appear

    def test_github_app_get_assessment_summary(self):
        """Test GitHub HTML assessment summary generation with GitHub App authentication."""
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        output = HTML(findings)

        provider = set_mocked_github_provider(
            auth_method="GitHub App Token",
            identity=GithubAppIdentityInfo(
                app_id=APP_ID, app_name="test-app", installations=["test-org"]
            ),
        )

        summary = output.get_assessment_summary(provider)
        logger.error(summary)

        # Check for expected content in the summary
        assert "GitHub Assessment Summary" in summary
        assert "GitHub Credentials" in summary
        assert "<b>GitHub App Name:</b> test-app" in summary
        assert "<b>Installations:</b> test-org" in summary
        assert "<b>GitHub authentication method:</b> GitHub App Token" in summary
        assert f"<b>GitHub App ID:</b> {APP_ID}" in summary

    def test_mongodbatlas_get_assessment_summary(self):
        """Test MongoDB Atlas HTML assessment summary generation."""
        findings = [generate_finding_output()]
        output = HTML(findings)
        provider = set_mocked_mongodbatlas_provider()

        summary = output.get_assessment_summary(provider)

        assert summary == mongodbatlas_html_assessment_summary

    def test_image_get_assessment_summary_with_registry(self):
        """Test Image HTML assessment summary with registry URL."""
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = "image"
        provider.registry = "myregistry.io"
        provider.images = ["nginx:latest", "alpine:3.18"]
        provider.auth_method = "Docker login"

        summary = output.get_assessment_summary(provider)

        assert summary == image_registry_html_assessment_summary

    def test_image_get_assessment_summary_with_images(self):
        """Test Image HTML assessment summary with image list."""
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = "image"
        provider.registry = None
        provider.images = ["nginx:latest", "alpine:3.18"]
        provider.auth_method = "No auth"

        summary = output.get_assessment_summary(provider)

        assert summary == image_list_html_assessment_summary

    def test_process_markdown_bold_text(self):
        """Test that **text** is converted to <strong>text</strong>"""
        test_text = "This is **bold text** and this is **also bold**"
        result = HTML.process_markdown(test_text)
        expected = (
            "This is <strong>bold text</strong> and this is <strong>also bold</strong>"
        )
        assert result == expected

    def test_process_markdown_italic_text(self):
        """Test that *text* is converted to <em>text</em>"""
        test_text = "This is *italic text* and this is *also italic*"
        result = HTML.process_markdown(test_text)
        expected = "This is <em>italic text</em> and this is <em>also italic</em>"
        assert result == expected

    def test_process_markdown_code_text(self):
        """Test that `text` is converted to <code>text</code>"""
        test_text = "Use the `ls` command to list files and `cd` to change directories"
        result = HTML.process_markdown(test_text)
        expected = "Use the <code>ls</code> command to list files and <code>cd</code> to change directories"
        assert result == expected

    def test_process_markdown_line_breaks(self):
        """Test that line breaks are converted to <br> tags"""
        test_text = "Line 1\nLine 2\nLine 3"
        result = HTML.process_markdown(test_text)
        expected = "Line 1<br />\nLine 2<br />\nLine 3"
        assert result == expected

    def test_process_markdown_mixed_formatting(self):
        """Test mixed markdown formatting"""
        test_text = "**Bold text** with *italic* and `code` elements.\n\nNew paragraph with **more bold**."
        result = HTML.process_markdown(test_text)
        expected = "<strong>Bold text</strong> with <em>italic</em> and <code>code</code> elements.<br />\n<br />\nNew paragraph with <strong>more bold</strong>."
        assert result == expected

    def test_process_markdown_empty_string(self):
        """Test that empty string returns empty string"""
        result = HTML.process_markdown("")
        assert result == ""

    def test_process_markdown_none_input(self):
        """Test that None input returns None"""
        result = HTML.process_markdown(None)
        assert result is None

    def test_process_markdown_no_markdown(self):
        """Test that plain text without markdown is returned unchanged"""
        test_text = "This is plain text without any markdown formatting"
        result = HTML.process_markdown(test_text)
        assert result == test_text

    def test_transform_with_markdown_risk(self):
        """Test that Risk field with markdown is properly converted"""
        findings = [
            generate_finding_output(
                risk="Outdated contacts delay **security notifications** and slow **incident response**",
                remediation_recommendation_url="https://hub.prowler.com/check/check-id",
            )
        ]
        html = HTML(findings)
        output_data = html.data[0]

        # Check that markdown is converted to HTML
        assert "<strong>security notifications</strong>" in output_data
        assert "<strong>incident response</strong>" in output_data

    def test_transform_with_markdown_recommendation(self):
        """Test that Recommendation field with markdown is properly converted"""
        findings = [
            generate_finding_output(
                risk="test-risk",
                remediation_recommendation_text="Adopt:\n- **Primary** and **alternate contacts**\n- Use `monitored aliases`",
                remediation_recommendation_url="https://hub.prowler.com/check/check-id",
            )
        ]
        html = HTML(findings)
        output_data = html.data[0]

        # Check that markdown is converted to HTML
        assert "<strong>Primary</strong>" in output_data
        assert "<strong>alternate contacts</strong>" in output_data
        assert "<code>monitored aliases</code>" in output_data
        assert "<br />" in output_data  # Line breaks converted
