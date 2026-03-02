import sys
from io import TextIOWrapper

import markdown

from prowler.config.config import (
    html_logo_url,
    prowler_version,
    square_logo_img,
    timestamp,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.output import Finding, Output
from prowler.lib.outputs.utils import parse_html_string, unroll_dict
from prowler.providers.common.provider import Provider


class HTML(Output):
    @staticmethod
    def process_markdown(text: str) -> str:
        """
        Process markdown syntax in text and convert to HTML using the markdown library.

        Args:
            text (str): Text containing markdown syntax

        Returns:
            str: HTML with markdown syntax converted
        """
        if not text:
            return text

        # Initialize markdown converter with safe mode to prevent XSS
        md = markdown.Markdown(extensions=["nl2br"])

        # Convert markdown to HTML
        html_content = md.convert(text)

        # Strip outer <p> tags if present, as we're embedding in existing HTML
        # Handle single paragraph case
        if (
            html_content.startswith("<p>")
            and html_content.endswith("</p>")
            and html_content.count("<p>") == 1
        ):
            html_content = html_content[3:-4]
        # Handle multiple paragraphs case - replace <p> and </p> with <br><br>
        elif "<p>" in html_content and "</p>" in html_content:
            html_content = html_content.replace("</p>\n<p>", "<br />\n<br />\n")
            html_content = html_content.replace("<p>", "")
            html_content = html_content.replace("</p>", "")

        return html_content

    def transform(self, findings: list[Finding]) -> None:
        """Transforms the findings into the HTML format.

        Args:
            findings (list[Finding]): a list of Finding objects

        """
        try:
            for finding in findings:
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

                self._data.append(
                    f"""
                        <tr class="{row_class}">
                            <td>{finding_status}</td>
                            <td>{finding.metadata.Severity.value}</td>
                            <td>{finding.metadata.ServiceName}</td>
                            <td>{finding.region.lower()}</td>
                            <td>{finding.metadata.CheckID.replace("_", "<wbr />_")}</td>
                            <td>{finding.metadata.CheckTitle}</td>
                            <td>{finding.resource_uid.replace("<", "&lt;").replace(">", "&gt;").replace("_", "<wbr />_")}</td>
                            <td>{parse_html_string(unroll_dict(finding.resource_tags))}</td>
                            <td>{finding.status_extended.replace("<", "&lt;").replace(">", "&gt;").replace("_", "<wbr />_")}</td>
                            <td><p class="show-read-more">{HTML.process_markdown(finding.metadata.Risk)}</p></td>
                            <td><p class="show-read-more">{HTML.process_markdown(finding.metadata.Remediation.Recommendation.Text)}</p> <a class="read-more" href="{finding.metadata.Remediation.Recommendation.Url}"><i class="fas fa-external-link-alt"></i></a></td>
                            <td><p class="show-read-more">{parse_html_string(unroll_dict(finding.compliance, separator=": "))}</p></td>
                        </tr>
                        """
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_data_to_file(self, provider: Provider, stats: dict) -> None:
        """
        Writes the findings to a file using the HTML format using the `Output._file_descriptor`.

        Args:
            provider (Provider): the provider object
            output_filename (str): the name of the output file
            output_directory (str): the directory where the output file will be saved
            stats (dict): the statistics of the findings
        """
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                if self._file_descriptor.tell() == 0:
                    HTML.write_header(
                        self._file_descriptor, provider, stats, self._from_cli
                    )
                for finding in self._data:
                    self._file_descriptor.write(finding)
                if self.close_file or self._from_cli:
                    HTML.write_footer(self._file_descriptor)
                    self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def write_header(
        file_descriptor: TextIOWrapper,
        provider: Provider,
        stats: dict,
        from_cli: bool = True,
    ) -> None:
        """
        Writes the header of the HTML file.

        Args:
            file_descriptor (file): the file descriptor to write the header
            provider (Provider): the provider object
            stats (dict): the statistics of the findings
            from_cli (bool): whether the request is from the CLI or not
        """
        try:
            file_descriptor.write(
                f"""<!DOCTYPE html>
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
                <b>Parameters used:</b> {" ".join(sys.argv[1:]) if from_cli else ""}
                </li>
                <li class="list-group-item">
                <b>Date:</b> {timestamp.isoformat()}
                </li>
            </ul>
            </div>
        </div>{HTML.get_assessment_summary(provider)}
            <div class="col-md-2">
            <div class="card">
                <div class="card-header">
                    Assessment Overview
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item">
                        <b>Total Findings:</b> {str(stats.get("findings_count", 0))}
                    </li>
                    <li class="list-group-item">
                        <b>Passed:</b> {str(stats.get("total_pass", 0))}
                    </li>
                    <li class="list-group-item">
                        <b>Passed (Muted):</b> {str(stats.get("total_muted_pass", 0))}
                    </li>
                    <li class="list-group-item">
                        <b>Failed:</b> {str(stats.get("total_fail", 0))}
                    </li>
                    <li class="list-group-item">
                        <b>Failed (Muted):</b> {str(stats.get("total_muted_fail", 0))}
                    </li>
                    <li class="list-group-item">
                        <b>Total Resources:</b> {str(stats.get("resources_count", 0))}
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
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )

    @staticmethod
    def write_footer(file_descriptor: TextIOWrapper) -> None:
        """
        Writes the footer of the HTML file.

        Args:
            file_descriptor (file): the file descriptor to write the footer
        """
        try:
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
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )

    @staticmethod
    def get_aws_assessment_summary(provider: Provider) -> str:
        """
        get_aws_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            profile = (
                provider.identity.profile
                if provider.identity.profile is not None
                else "default"
            )
            if isinstance(provider.identity.audited_regions, list):
                audited_regions = " ".join(provider.identity.audited_regions)
            elif not provider.identity.audited_regions:
                audited_regions = "All Regions"
            else:
                audited_regions = ", ".join(provider.identity.audited_regions)
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            AWS Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>AWS Account:</b> {provider.identity.account}
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
                            <b>User Id:</b> {provider.identity.user_id}
                            </li>
                            <li class="list-group-item">
                                <b>Caller Identity ARN:</b> {provider.identity.identity_arn}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_azure_assessment_summary(provider: Provider) -> str:
        """
        get_azure_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            printed_subscriptions = []
            for key, value in provider.identity.subscriptions.items():
                intermediate = f"{key} : {value}"
                printed_subscriptions.append(intermediate)

            # check if identity is str(coming from SP) or dict(coming from browser or)
            if isinstance(provider.identity.identity_id, dict):
                html_identity = provider.identity.identity_id.get(
                    "userPrincipalName", "Identity not found"
                )
            else:
                html_identity = provider.identity.identity_id
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Azure Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>Azure Tenant IDs:</b> {" ".join(provider.identity.tenant_ids)}
                            </li>
                            <li class="list-group-item">
                                <b>Azure Tenant Domain:</b> {provider.identity.tenant_domain}
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
                            <b>Azure Identity Type:</b> {provider.identity.identity_type}
                            </li>
                            <li class="list-group-item">
                                <b>Azure Identity ID:</b> {html_identity}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_gcp_assessment_summary(provider: Provider) -> str:
        """
        get_gcp_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            try:
                getattr(provider.session, "_service_account_email")
                profile = (
                    provider.session._service_account_email
                    if provider.session._service_account_email is not None
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
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_kubernetes_assessment_summary(provider: Provider) -> str:
        """
        get_kubernetes_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Kubernetes Assessment Summary
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>Kubernetes Cluster:</b> {provider.identity.cluster}
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
                                <b>Kubernetes Context:</b> {provider.identity.context}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_github_assessment_summary(provider: Provider) -> str:
        """
        get_github_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            if hasattr(provider.identity, "account_name"):
                # GithubIdentityInfo (Personal Access Token, OAuth)
                account_info_items = f"""
                            <li class="list-group-item">
                                <b>GitHub account:</b> {provider.identity.account_name}
                            </li>
                            """
                # Add email if available
                if (
                    hasattr(provider.identity, "account_email")
                    and provider.identity.account_email
                ):
                    account_info_items += f"""
                                <li class="list-group-item">
                                    <b>GitHub account email:</b> {provider.identity.account_email}
                                </li>"""
            elif hasattr(provider.identity, "app_id"):
                # GithubAppIdentityInfo (GitHub App)
                # Assessment items: App Name and Installations
                account_info_items = f"""
                                <li class="list-group-item">
                                    <b>GitHub App Name:</b> {provider.identity.app_name}
                                </li>"""
                # Add installations if available
                if (
                    hasattr(provider.identity, "installations")
                    and provider.identity.installations
                ):
                    installations_display = ", ".join(provider.identity.installations)
                    account_info_items += f"""
                            <li class="list-group-item">
                                <b>Installations:</b> {installations_display}
                            </li>"""
                else:
                    account_info_items += """
                            <li class="list-group-item">
                                <b>Installations:</b> No installations found
                            </li>"""

                # Credentials items: Authentication method and App ID
                credentials_items = f"""
                            <li class="list-group-item">
                                <b>GitHub authentication method:</b> {provider.auth_method}
                            </li>
                            <li class="list-group-item">
                                <b>GitHub App ID:</b> {provider.identity.app_id}
                            </li>"""
            else:
                # Fallback for other identity types
                account_info_items = ""
                credentials_items = f"""
                            <li class="list-group-item">
                                <b>GitHub authentication method:</b> {provider.auth_method}
                            </li>"""

            # For PAT/OAuth, use default credentials structure
            if hasattr(provider.identity, "account_name"):
                credentials_items = f"""
                            <li class="list-group-item">
                                <b>GitHub authentication method:</b> {provider.auth_method}
                            </li>"""

            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            GitHub Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            {account_info_items}
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            GitHub Credentials
                        </div>
                        <ul class="list-group list-group-flush">
                            {credentials_items}
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_m365_assessment_summary(provider: Provider) -> str:
        """
        get_m365_assessment_summary gets the HTML assessment summary for the provider
        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            M365 Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>M365 Tenant Domain:</b> {
                provider.identity.tenant_domain
            }
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
                            <b>M365 Identity Type:</b> {provider.identity.identity_type}
                            </li>
                            <li class="list-group-item">
                                <b>M365 Identity ID:</b> {provider.identity.identity_id}
                            </li>
                            {
                f'''<li class="list-group-item">
                                <b>M365 User:</b> {provider.identity.user}
                            </li>'''
                if hasattr(provider.identity, "user")
                and provider.identity.user is not None
                else ""
            }
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    def get_nhn_assessment_summary(provider: Provider) -> str:
        """
        get_nhn_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            NHN Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>NHN Tenant Domain:</b> {provider.identity.tenant_domain}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        NHN Credentials
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>NHN Identity Type:</b> {provider.identity.identity_type}
                            </li>
                            <li class="list-group-item">
                                <b>NHN Identity ID:</b> {provider.identity.identity_id}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_mongodbatlas_assessment_summary(provider: Provider) -> str:
        """
        get_mongodbatlas_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            MongoDB Atlas Assessment Summary
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>MongoDB Atlas organization:</b> {provider.identity.organization_name}
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
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_iac_assessment_summary(provider: Provider) -> str:
        """
        get_iac_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            IAC Assessment Summary
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                {"<b>IAC repository URL:</b> " + provider.scan_repository_url if provider.scan_repository_url else "<b>IAC path:</b> " + provider.scan_path}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            IAC Credentials
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>IAC authentication method:</b> {provider.auth_method}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_image_assessment_summary(provider: Provider) -> str:
        """
        get_image_assessment_summary gets the HTML assessment summary for the Image provider

        Args:
            provider (Provider): the Image provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            if provider.registry:
                target_info = f"<b>Registry URL:</b> {provider.registry}"
            else:
                target_info = f'<b>Images:</b> {", ".join(provider.images)}'

            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Image Assessment Summary
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                {target_info}
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
                                <b>Image authentication method:</b> {provider.auth_method}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_llm_assessment_summary(provider: Provider) -> str:
        """
        get_llm_assessment_summary gets the HTML assessment summary for the LLM provider

        Args:
            provider (Provider): the LLM provider object

        Returns:
            str: HTML assessment summary for the LLM provider
        """
        try:
            return f"""
                <div class="card">
                    <div class="card-header">
                        <h5 class="card-title mb-0">
                            <i class="fas fa-robot"></i> LLM Security Assessment Summary
                        </h5>
                    </div>
                    <div class="card-body">
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>Target LLM:</b> {provider.model}
                            </li>
                            <li class="list-group-item">
                                <b>Plugins:</b> {", ".join(provider.plugins)}
                            </li>
                            <li class="list-group-item">
                                <b>Max concurrency:</b> {provider.max_concurrency}
                            </li>
                            <li class="list-group-item">
                                <b>Config file:</b> {provider.config_path if provider.config_path else "Using promptfoo defaults"}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_oraclecloud_assessment_summary(provider: Provider) -> str:
        """
        get_oraclecloud_assessment_summary gets the HTML assessment summary for the OracleCloud provider

        Args:
            provider (Provider): the OracleCloud provider object

        Returns:
            str: HTML assessment summary for the OracleCloud provider
        """
        try:
            profile = getattr(provider.session, "profile", "default")
            if profile is None:
                profile = "instance-principal"
            tenancy_name = getattr(provider.identity, "tenancy_name", "unknown")
            tenancy_id = getattr(provider.identity, "tenancy_id", "unknown")

            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            OracleCloud Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>OracleCloud Tenancy:</b> {tenancy_name if tenancy_name != "unknown" else tenancy_id}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            OracleCloud Credentials
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>Profile:</b> {profile}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_cloudflare_assessment_summary(provider: Provider) -> str:
        """
        get_cloudflare_assessment_summary gets the HTML assessment summary for the Cloudflare provider

        Args:
            provider (Provider): the Cloudflare provider object

        Returns:
            str: HTML assessment summary for the Cloudflare provider
        """
        try:
            # Build assessment summary items (only non-None values)
            assessment_items = ""
            if provider.accounts:
                accounts = ", ".join([acc.id for acc in provider.accounts])
                assessment_items += f"""
                            <li class="list-group-item">
                                <b>Accounts:</b> {accounts}
                            </li>"""

            # Build credentials items (only non-None values)
            credentials_items = ""

            # Authentication method
            if provider.session.api_token:
                credentials_items += """
                            <li class="list-group-item">
                                <b>Authentication:</b> API Token
                            </li>"""
            elif provider.session.api_key and provider.session.api_email:
                credentials_items += """
                            <li class="list-group-item">
                                <b>Authentication:</b> API Key + Email
                            </li>"""

            # Email (from identity or session)
            email = getattr(provider.identity, "email", None) or getattr(
                provider.session, "api_email", None
            )
            if email:
                credentials_items += f"""
                            <li class="list-group-item">
                                <b>Email:</b> {email}
                            </li>"""

            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Cloudflare Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">{assessment_items}
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            Cloudflare Credentials
                        </div>
                        <ul class="list-group list-group-flush">{credentials_items}
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_alibabacloud_assessment_summary(provider: Provider) -> str:
        """
        get_alibabacloud_assessment_summary gets the HTML assessment summary for the Alibaba Cloud provider

        Args:
            provider (Provider): the Alibaba Cloud provider object

        Returns:
            str: HTML assessment summary for the Alibaba Cloud provider
        """
        try:
            account_id = getattr(provider.identity, "account_id", "unknown")
            account_name = getattr(provider.identity, "account_name", "")
            audited_regions = getattr(
                provider.identity, "audited_regions", "All Regions"
            )
            identity_arn = getattr(provider.identity, "identity_arn", "unknown")
            user_name = getattr(provider.identity, "user_name", "unknown")

            account_name_item = (
                f"""
                            <li class="list-group-item">
                                <b>Account Name:</b> {account_name}
                            </li>"""
                if account_name
                else ""
            )

            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Alibaba Cloud Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>Account ID:</b> {account_id}
                            </li>
                            {account_name_item}
                            <li class="list-group-item">
                                <b>Audited Regions:</b> {audited_regions}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            Alibaba Cloud Credentials
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>User Name:</b> {user_name}
                            </li>
                            <li class="list-group-item">
                                <b>Identity ARN:</b> {identity_arn}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_openstack_assessment_summary(provider: Provider) -> str:
        """
        get_openstack_assessment_summary gets the HTML assessment summary for the OpenStack provider

        Args:
            provider (Provider): the OpenStack provider object

        Returns:
            str: HTML assessment summary for the OpenStack provider
        """
        try:
            project_id = getattr(provider.identity, "project_id", "unknown")
            project_name = getattr(provider.identity, "project_name", "")
            region_name = getattr(provider.identity, "region_name", "unknown")
            username = getattr(provider.identity, "username", "unknown")
            user_id = getattr(provider.identity, "user_id", "")

            project_name_item = (
                f"""
                            <li class="list-group-item">
                                <b>Project Name:</b> {project_name}
                            </li>"""
                if project_name
                else ""
            )

            user_id_item = (
                f"""
                            <li class="list-group-item">
                                <b>User ID:</b> {user_id}
                            </li>"""
                if user_id
                else ""
            )

            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            OpenStack Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>Project ID:</b> {project_id}
                            </li>
                            {project_name_item}
                            <li class="list-group-item">
                                <b>Region:</b> {region_name}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            OpenStack Credentials
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>Username:</b> {username}
                            </li>
                            {user_id_item}
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_googleworkspace_assessment_summary(provider: Provider) -> str:
        """
        get_googleworkspace_assessment_summary gets the HTML assessment summary for the Google Workspace provider

        Args:
            provider (Provider): the Google Workspace provider object

        Returns:
            str: HTML assessment summary for the Google Workspace provider
        """
        try:
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Google Workspace Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>Domain:</b> {provider.identity.domain}
                            </li>
                            <li class="list-group-item">
                                <b>Customer ID:</b> {provider.identity.customer_id}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            Google Workspace Credentials
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>Delegated User:</b> {provider.identity.delegated_user}
                            </li>
                            <li class="list-group-item">
                                <b>Authentication Method:</b> Service Account with Domain-Wide Delegation
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_assessment_summary(provider: Provider) -> str:
        """
        get_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            # This is based in the Provider_provider class
            # It is not pretty but useful
            # AWS_provider --> aws
            # GCP_provider --> gcp
            # GitHub_provider --> github
            # Azure_provider --> azure
            # Kubernetes_provider --> kubernetes

            # Dynamically get the Provider quick inventory handler
            provider_html_assessment_summary_function = (
                f"get_{provider.type}_assessment_summary"
            )
            return getattr(HTML, provider_html_assessment_summary_function)(provider)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""
