import re
import sys
from io import StringIO

import pytest
from mock import MagicMock, patch

from prowler.config.config import prowler_version, timestamp
from prowler.lib.cli.redact import redact_argv
from prowler.lib.logger import logger
from prowler.lib.outputs.html.html import HTML
from prowler.providers.github.models import GithubAppIdentityInfo
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider
from tests.providers.azure.azure_fixtures import set_mocked_azure_provider
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider
from tests.providers.github.github_fixtures import APP_ID, set_mocked_github_provider
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    set_mocked_googleworkspace_provider,
)
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
                <b>Parameters used:</b> {redact_argv(args)}
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


def _setup_aws_xss(provider, payload):
    provider.identity.account = payload
    provider.identity.profile = payload
    provider.identity.audited_regions = [payload]
    provider.identity.user_id = payload
    provider.identity.identity_arn = payload


def _setup_azure_xss(provider, payload):
    provider.identity.tenant_ids = [payload]
    provider.identity.tenant_domain = payload
    provider.identity.subscriptions = {payload: payload}
    provider.identity.identity_type = payload
    provider.identity.identity_id = payload


def _setup_gcp_xss(provider, payload):
    provider.project_ids = [payload]
    provider.session._service_account_email = payload


def _setup_kubernetes_xss(provider, payload):
    provider.identity.cluster = payload
    provider.identity.context = payload


def _setup_github_xss(provider, payload):
    provider.identity = MagicMock(spec=["account_name", "account_email"])
    provider.identity.account_name = payload
    provider.identity.account_email = payload
    provider.auth_method = payload


def _setup_m365_xss(provider, payload):
    provider.identity.tenant_domain = payload
    provider.identity.identity_type = payload
    provider.identity.identity_id = payload
    provider.identity.user = payload


def _setup_nhn_xss(provider, payload):
    provider.identity.tenant_domain = payload
    provider.identity.identity_type = payload
    provider.identity.identity_id = payload


def _setup_mongodbatlas_xss(provider, payload):
    provider.identity.organization_name = payload


def _setup_iac_xss(provider, payload):
    provider.scan_repository_url = payload
    provider.scan_path = None
    provider.auth_method = payload


def _setup_image_xss(provider, payload):
    provider.registry = payload
    provider.images = [payload]
    provider.auth_method = payload


def _setup_llm_xss(provider, payload):
    provider.model = payload
    provider.plugins = [payload]
    provider.max_concurrency = payload
    provider.config_path = payload


def _setup_oraclecloud_xss(provider, payload):
    provider.session.profile = payload
    provider.identity.tenancy_name = payload
    provider.identity.tenancy_id = payload


def _setup_stackit_xss(provider, payload):
    provider.identity.project_id = payload
    provider.identity.project_name = payload
    provider.identity.audited_regions = {payload}


def _setup_cloudflare_xss(provider, payload):
    account = MagicMock()
    account.id = payload
    provider.accounts = [account]
    provider.session.api_token = "token"
    provider.session.api_key = None
    provider.session.api_email = None
    provider.identity.email = payload


def _setup_alibabacloud_xss(provider, payload):
    provider.identity.account_id = payload
    provider.identity.account_name = payload
    provider.identity.audited_regions = payload
    provider.identity.identity_arn = payload
    provider.identity.user_name = payload


def _setup_openstack_xss(provider, payload):
    provider.identity.project_id = payload
    provider.identity.project_name = payload
    provider.identity.region_name = payload
    provider.identity.username = payload
    provider.identity.user_id = payload


def _setup_googleworkspace_xss(provider, payload):
    provider.identity.domain = payload
    provider.identity.customer_id = payload
    provider.identity.delegated_user = payload


def _setup_e2enetworks_xss(provider, payload):
    provider.identity.project_id = payload
    provider.identity.locations = [payload]


def _setup_vercel_xss(provider, payload):
    team = MagicMock()
    team.name = payload
    team.id = payload
    provider.identity.team = team
    provider.identity.email = payload
    provider.identity.username = payload


def _setup_okta_xss(provider, payload):
    provider.identity.org_domain = payload
    provider.auth_method = payload
    provider.identity.client_id = payload


def _setup_scaleway_xss(provider, payload):
    provider.identity.organization_id = payload
    provider.session.access_key = payload
    provider.identity.bearer_type = payload
    provider.identity.bearer_email = payload
    provider.identity.bearer_id = payload
    provider.session.default_region = payload


def _setup_linode_xss(provider, payload):
    provider.identity.username = payload
    provider.identity.email = payload
    provider.identity.account_id = payload


def _setup_huaweicloud_xss(provider, payload):
    provider.identity.account_id = payload
    provider.identity.account_name = payload
    provider.identity.profile = payload
    provider.identity.regions = {payload}
    provider.identity.domain_id = payload
    provider.identity.user_id = payload
    provider.identity.user_name = payload
    provider.identity.identity_type = payload


PROVIDER_XSS_SETUPS = [
    ("aws", _setup_aws_xss),
    ("azure", _setup_azure_xss),
    ("gcp", _setup_gcp_xss),
    ("kubernetes", _setup_kubernetes_xss),
    ("github", _setup_github_xss),
    ("m365", _setup_m365_xss),
    ("nhn", _setup_nhn_xss),
    ("mongodbatlas", _setup_mongodbatlas_xss),
    ("iac", _setup_iac_xss),
    ("image", _setup_image_xss),
    ("llm", _setup_llm_xss),
    ("oraclecloud", _setup_oraclecloud_xss),
    ("stackit", _setup_stackit_xss),
    ("cloudflare", _setup_cloudflare_xss),
    ("alibabacloud", _setup_alibabacloud_xss),
    ("openstack", _setup_openstack_xss),
    ("googleworkspace", _setup_googleworkspace_xss),
    ("e2enetworks", _setup_e2enetworks_xss),
    ("vercel", _setup_vercel_xss),
    ("okta", _setup_okta_xss),
    ("scaleway", _setup_scaleway_xss),
    ("linode", _setup_linode_xss),
    ("huaweicloud", _setup_huaweicloud_xss),
]


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

    def test_transform_escapes_provider_originated_fields(self):
        xss_payload = '<img src=x onerror="window.PROWLER_TAG_XSS=1">'
        findings = [
            generate_finding_output(
                region="REGION&<>'\"",
                resource_uid="resource&<>'\"_uid",
                resource_tags={f"key&<>'\"{xss_payload}": f"value&<>'\"{xss_payload}"},
                status_extended=f"status&<>'\"_{xss_payload}",
                remediation_recommendation_url="https://hub.prowler.com/check/check-id",
            )
        ]

        output_data = HTML(findings).data[0]

        assert xss_payload not in output_data
        assert "region&amp;&lt;&gt;&#39;&#34;" in output_data
        assert "resource&amp;&lt;&gt;&#39;&#34;<wbr />_uid" in output_data
        assert "status&amp;&lt;&gt;&#39;&#34;<wbr />_&lt;img" in output_data
        assert "&#x2022;key&amp;&lt;&gt;&#39;&#34;&lt;img" in output_data
        assert "=value&amp;&lt;&gt;&#39;&#34;&lt;img" in output_data

    def test_transform_escapes_metadata_fields(self):
        finding = generate_finding_output()
        finding.metadata.Severity = MagicMock(value='<img data-field="severity" src=x>')
        finding.metadata.ServiceName = '<img data-field="service" src=x>'
        finding.metadata.CheckID = '<img data-field="check_id" src=x>_suffix'
        finding.metadata.CheckTitle = '<img data-field="check_title" src=x>'
        finding.metadata.Risk = '**Risk** <img data-field="risk" src=x>'
        finding.metadata.Remediation.Recommendation.Text = (
            '**Recommendation** <img data-field="recommendation" src=x>'
        )
        finding.metadata.Remediation.Recommendation.Url = (
            'https://example.com"><img data-field="url" src=x>'
        )

        output_data = HTML([finding]).data[0]

        raw_payloads = (
            '<img data-field="severity" src=x>',
            '<img data-field="service" src=x>',
            '<img data-field="check_id" src=x>_suffix',
            '<img data-field="check_title" src=x>',
            '<img data-field="risk" src=x>',
            '<img data-field="recommendation" src=x>',
            'href="https://example.com"><img data-field="url" src=x>"',
        )
        for payload in raw_payloads:
            assert payload not in output_data

        assert "&lt;img data-field=&#34;severity&#34; src=x&gt;" in output_data
        assert "&lt;img data-field=&#34;service&#34; src=x&gt;" in output_data
        assert (
            "&lt;img data-field=&#34;check<wbr />_id&#34; src=x&gt;<wbr />_suffix"
            in output_data
        )
        assert "&lt;img data-field=&#34;check_title&#34; src=x&gt;" in output_data
        assert (
            "<strong>Risk</strong> &lt;img data-field=&#34;risk&#34; src=x&gt;"
            in output_data
        )
        assert (
            "<strong>Recommendation</strong> &lt;img "
            "data-field=&#34;recommendation&#34; src=x&gt;" in output_data
        )
        assert (
            'href="https://example.com&#34;&gt;&lt;img '
            'data-field=&#34;url&#34; src=x&gt;"' in output_data
        )

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

    def test_googleworkspace_get_assessment_summary(self):
        """Test Google Workspace HTML assessment summary generation."""
        findings = [generate_finding_output()]
        output = HTML(findings)
        provider = set_mocked_googleworkspace_provider()

        summary = output.get_assessment_summary(provider)

        assert "Google Workspace Assessment Summary" in summary
        assert "Google Workspace Credentials" in summary
        assert "<b>Domain:</b> test-company.com" in summary
        assert "<b>Customer ID:</b> C1234567" in summary
        assert "<b>Delegated User:</b> prowler-reader@test-company.com" in summary
        assert (
            "<b>Authentication Method:</b> Service Account with Domain-Wide Delegation"
            in summary
        )

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

    def test_stackit_get_assessment_summary(self):
        """Test StackIT HTML assessment summary shows the project ID."""
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = "stackit"
        provider.identity.project_id = "f033ea6d-8697-40eb-a60e-acfa9128480d"
        provider.identity.project_name = "ProwlerDev"
        provider.identity.audited_regions = {"eu01", "eu02"}

        summary = output.get_assessment_summary(provider)

        assert "StackIT Assessment Summary" in summary
        assert "StackIT Credentials" in summary
        assert "<b>Project ID:</b> f033ea6d-8697-40eb-a60e-acfa9128480d" in summary
        assert "<b>Project Name:</b> ProwlerDev" in summary
        assert "<b>Regions:</b> eu01, eu02" in summary
        assert "<b>Authentication Type:</b> Service Account Key" in summary

    def test_stackit_get_assessment_summary_without_project_name(self):
        """Project ID is always shown; the Project Name line is omitted when
        the service account cannot read it from Resource Manager."""
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = "stackit"
        provider.identity.project_id = "f033ea6d-8697-40eb-a60e-acfa9128480d"
        provider.identity.project_name = ""
        provider.identity.audited_regions = {"eu01"}

        summary = output.get_assessment_summary(provider)

        assert "<b>Project ID:</b> f033ea6d-8697-40eb-a60e-acfa9128480d" in summary
        assert "<b>Project Name:</b>" not in summary

    def test_e2enetworks_get_assessment_summary(self):
        """Test E2E Networks HTML assessment summary shows project and locations."""
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = "e2enetworks"
        provider.identity.project_id = 12345
        provider.identity.locations = ["Delhi", "Chennai"]

        summary = output.get_assessment_summary(provider)

        assert "E2E Networks Assessment Summary" in summary
        assert "<b>Project ID:</b> 12345" in summary
        assert "<b>Locations:</b> Delhi, Chennai" in summary
        assert "API Key + Bearer Token" in summary

    def test_e2enetworks_get_assessment_summary_escapes_locations(self):
        """Test E2E Networks HTML assessment summary escapes user-controlled locations."""
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = "e2enetworks"
        provider.identity.project_id = 12345
        provider.identity.locations = ['Delhi"><script>alert(1)</script>']

        summary = output.get_assessment_summary(provider)

        assert "<script>alert(1)</script>" not in summary
        assert "Delhi&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in summary

    @pytest.mark.parametrize(
        "provider_type,setup_fn",
        PROVIDER_XSS_SETUPS,
        ids=[t for t, _ in PROVIDER_XSS_SETUPS],
    )
    def test_get_assessment_summary_escapes_provider_identity(
        self, provider_type, setup_fn
    ):
        """Every provider header must HTML-escape tenant-controlled identity fields."""
        payload = "<script>alert(1)</script>"
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = provider_type
        setup_fn(provider, payload)

        summary = output.get_assessment_summary(provider)

        assert payload not in summary
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in summary

    def test_provider_xss_setups_covers_every_assessment_summary_method(self):
        """Adding a new get_<provider>_assessment_summary without a PROVIDER_XSS_SETUPS
        entry must fail this test, so the escape guarantee cannot silently regress."""
        pattern = re.compile(r"^get_(.+)_assessment_summary$")
        discovered = set()
        for name in dir(HTML):
            match = pattern.match(name)
            if match:
                discovered.add(match.group(1))

        covered = {ptype for ptype, _ in PROVIDER_XSS_SETUPS}

        missing = discovered - covered
        extra = covered - discovered
        assert (
            not missing
        ), f"providers without XSS coverage in PROVIDER_XSS_SETUPS: {sorted(missing)}"
        assert (
            not extra
        ), f"PROVIDER_XSS_SETUPS entries with no matching HTML method: {sorted(extra)}"

    def test_github_app_get_assessment_summary_escapes_app_identity(self):
        """The GitHub App branch (elif hasattr app_id) must escape app_name/app_id/installations,
        which the PAT setup does not exercise."""
        payload = "<script>alert(1)</script>"
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = "github"
        provider.identity = MagicMock(spec=["app_id", "app_name", "installations"])
        provider.identity.app_id = payload
        provider.identity.app_name = payload
        provider.identity.installations = [payload]
        provider.auth_method = payload

        summary = output.get_assessment_summary(provider)

        assert payload not in summary
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in summary

    def test_iac_get_assessment_summary_escapes_scan_path(self):
        """The IAC scan_path branch (else of `if scan_repository_url`) must escape it."""
        payload = "<script>alert(1)</script>"
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = "iac"
        provider.scan_repository_url = None
        provider.scan_path = payload
        provider.auth_method = payload

        summary = output.get_assessment_summary(provider)

        assert payload not in summary
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in summary

    def test_image_get_assessment_summary_escapes_images_list(self):
        """The Image `else` branch (no registry, images list) must escape each image."""
        payload = "<script>alert(1)</script>"
        findings = [generate_finding_output()]
        output = HTML(findings)

        provider = MagicMock()
        provider.type = "image"
        provider.registry = None
        provider.images = [payload]
        provider.auth_method = payload

        summary = output.get_assessment_summary(provider)

        assert payload not in summary
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in summary

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

    def test_process_markdown_strips_javascript_links(self):
        """Markdown links with javascript: scheme must not produce clickable hrefs."""
        result = HTML.process_markdown(
            "Click [here](javascript:alert(&#34;xss&#34;)) to continue"
        )
        assert 'href="javascript:' not in result
        assert "here" in result

    def test_process_markdown_keeps_https_links(self):
        """Markdown links with https: scheme must be preserved."""
        result = HTML.process_markdown("[docs](https://docs.prowler.com)")
        assert 'href="https://docs.prowler.com"' in result
        assert "<a" in result

    def test_transform_recommendation_url_javascript_scheme_is_blocked(self):
        """Recommendation.Url with javascript: scheme must render as empty href."""
        finding = generate_finding_output(
            remediation_recommendation_url="https://hub.prowler.com/check/check-id"
        )
        finding.metadata.Remediation.Recommendation.Url = "javascript:alert(1)"
        output_data = HTML([finding]).data[0]
        assert 'href="javascript:' not in output_data
        assert 'href=""' in output_data

    def test_transform_recommendation_url_https_is_kept(self):
        """Recommendation.Url with https: scheme must appear unchanged in href."""
        findings = [
            generate_finding_output(
                remediation_recommendation_url="https://hub.prowler.com/check/check-id"
            )
        ]
        output_data = HTML(findings).data[0]
        assert 'href="https://hub.prowler.com/check/check-id"' in output_data
