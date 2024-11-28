from json import dump
from os import SEEK_SET, getenv
from typing import Optional
import requests
import sys
from io import TextIOWrapper

from pydantic import BaseModel, validator

from prowler.config.config import prowler_version, timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output
from prowler.lib.utils.utils import hash_sha512

import openai

# Duplicate as little of the HTML output code as possible.
import html
from prowler.lib.outputs.utils import parse_html_string, unroll_dict
from prowler.config.config import (
    html_logo_url,
    prowler_version,
    square_logo_img,
    timestamp,
)
from prowler.providers.common.provider import Provider
import openai

class BACK2CODE(Output):
    """
    """
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
                BACK2CODE.write_header(self._file_descriptor, provider, stats)
                for finding in self._data:
                    self._file_descriptor.write(finding)
                BACK2CODE.write_footer(self._file_descriptor)
                # Close file descriptor
                self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def write_header(
        file_descriptor: TextIOWrapper, provider: Provider, stats: dict
        ) -> None:
        """
        Writes the header of the HTML file.

        Args:
            file_descriptor (file): the file descriptor to write the header
            provider (Provider): the provider object
            stats (dict): the statistics of the findings
        """
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
            <title>Prowler - Back2Code Results</title>
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
                        Failed Resources with Available Source Code
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
                </div>
                </div>
                </div>
                </div>
                <div class="row-mt-3">
                <div class="col-md-12">
                    <table class="table compact stripe row-border ordering" id="findingsTable" data-order='[[ 5, "asc" ]]' data-page-length='100'>
                    <thead class="thead-light">
                        <tr>
                            <th scope="col">Service Name</th>
                            <th style="width:20%" scope="col">Check ID</th>
                            <th style="width:20%" scope="col">Check Title</th>
                            <th scope="col">Region</th>
                            <th scope="col">Status</th>
                            <th scope="col">Severity</th>
                            <th scope="col">Service Name</th>
                            <th scope="col">Resource ID</th>
                            <th scope="col">AI Remediation Advice</th>
                            <th scope="col">Source Code References</th>
                            <th scope="col">Risk</th>
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
                        var maxLength = 60;
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
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )


    def transform(self, findings: list[Finding]) -> None:
        """
  
        """

        #Create our SCM cache object. This prevents us from making the same API calls (currently only to github.com) multiple times.
        global scmFinderLookupCache 
        scmFinderLookupCache = ScmFinderLookupCache()

        # Get the API key from the environment variable
        openai_key = getenv("OPENAI_API_KEY")

        if not openai_key:
            openai_key = None # We can still run the code without an API key, but we won't get AI suggestions.

        # Our output for this module will be cleaner and quicker if we sort by Check and Resource.
        # We can then generate our AI suggestions for each unique check, vs each unique finding.
        findingsByResource = {}
        findingsByCheck = {}
        findingsByCheckExampleAISolution = {} 
        
        try:
            for finding in findings:
                # No point digging for code if the finding is not a failed one.
                if type(finding.status) is not str:
                    normalizeFindingStatus = finding.status.value
                else:
                    normalizeFindingStatus = finding.status
                if normalizeFindingStatus == 'FAIL':
                    filesFromCommit = []
                    # Try to find a maching public source code commit for the finding based on tags (from yor.io)
                    if finding.resource_tags.__len__() > 0:
                        enough_breadcrumbs = False
                        if "yor_trace" in finding.resource_tags:
                            enough_breadcrumbs = True
                        if "git_commit" in finding.resource_tags:
                            enough_breadcrumbs = True
                        if enough_breadcrumbs:
                            # Only call github&gitlab finder if we have enough breadcrumbs.
                            filesFromCommit = self.finder_public_scm_runner(self, finding.resource_tags)
                            # If we found files from a commit, append to the finding so we can sort|filter|group|uniqie for our AI recommendations
                            # otherwise we churn generating the same recommendations for potentially multiple resources.
                            finding.back2code = filesFromCommit

                # Sort findings by check and Resource
                if isinstance(finding, Finding): # We do not want account-specific checks in our data as they have a different data model for metadata.
                    if finding.metadata.CheckID not in findingsByCheck:
                        findingsByCheck[finding.metadata.CheckID] = []
                        findingsByCheck[finding.metadata.CheckID].append(finding)
                    else:
                        findingsByCheck[finding.metadata.CheckID].append(finding)
                    
                    if finding.resource_uid not in findingsByResource:
                        findingsByResource[finding.resource_uid] = []
                        findingsByResource[finding.resource_uid].append(finding)
                    else:
                        findingsByResource[finding.resource_uid].append(finding)

        except Exception as error:
            logger.error(
                f"Errors in Back2Code output. Do not rely on results without confirming this error. report goto.prowler.com/slack \n Error is: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        # Pick a single finding per check to generate AI suggestions for.
        # Add to check metadata before finally rendering outputs.
        try:

            for check in findingsByCheck:
                if check in findingsByCheckExampleAISolution:
                    continue # We've already generated one AI suggestion for this check, point others to the example. May expose option to generate more in the future (using more OpenAI credits and taking longer).
                for resource in findingsByCheck[check]:
                    if resource.back2code is not None:
                        terraform_file_globs = ""
                        if openai_key is not None: #We have openAI creds. Generate additional fix/info.
                            for file in resource.back2code.files:
                                if ".tf" in file.fileNameWithPath:
                                        terraform_file_globs = terraform_file_globs + file.fileRawContent
                            improved_output = self.improve_terraform(terraform_file_globs, finding.metadata.Description)
                            if improved_output:
                                #print(f"AI Generated suggestions for failed finding: {finding.metadata.CheckTitle}")
                                #print(f"Prowler located the original code at: {filesFromCommit.scmSourceName}, repository: {filesFromCommit.git_repo}/{filesFromCommit.git_org},  commit: {filesFromCommit.git_commit} \n ")
                                resource.back2code_aisuggestions = improved_output
                                findingsByCheckExampleAISolution[check] = [resource,improved_output]
                            else:
                                #print("No improvements suggested by OpenAI. However, the following source code commits locations may be relevant to permenantly fixing your failed finding!:\n") 
                                #print(f"Prowler located the original code at: {filesFromCommit.scmSourceName}, repository: {filesFromCommit.git_repo}/{filesFromCommit.git_org},  commit: {filesFromCommit.git_commit} \n ")
                                continue

        
                    if resource.status.value == 'FAIL':   
                        backtoCodeResource = ""        
                        row_class = "p-3 mb-2 bg-success-custom"
                        finding_status = resource.status.value
                        # Change the status of the finding if it's muted
                        if resource.muted:
                            finding_status = f"MUTED ({finding_status})"
                            row_class = "table-warning"
                        if resource.status == "MANUAL":
                            row_class = "table-info"
                        elif resource.status == "FAIL":
                            row_class = "table-info" # Made this blue for now. We can change back to red if we want, but ALL results on this page will be the same colour.
                        #if finding.resource_tags is not None:
                        #    for tag in finding.resource_tags:
                        #        if tag == "yor_trace":
                        #            finding.resource_tags[tag] = f'<a class="{finding.resource_tags[tag]}" href="https://github.com/search?q={finding.resource_tags[tag]}&type=code">{finding.resource_tags[tag]}</a>'
                        #        if tag == "git_commit":
                        #            finding.resource_tags[tag] = f'<a class="{finding.resource_tags[tag]}" href="https://github.com/search?q={finding.resource_tags[tag]}&type=commits">{finding.resource_tags[tag]}</a>'
                        if resource.back2code is not None:
                            if resource == findingsByCheckExampleAISolution[check][0]:
                                backtoCodeResource = html.escape(parse_html_string(resource.back2code_aisuggestions))
                            else:
                                backtoCodeResource = f"Source code found, however AI generated recommendations already exist for this check type. See {findingsByCheckExampleAISolution[check][0]} for more information."

                        else:
                            backtoCodeResource = "No Source Code Found or OpenAI API Key not set."

                        self._data.append(
                            #<tr>
                            #        1 <th scope="col">Service Name</th>
                            #        2 <th style="width:20%" scope="col">Check ID</th>
                            #        3 <th style="width:20%" scope="col">Check Title</th>
                            #        4 <th scope="col">Region</th>
                            #        5 <th scope="col">Status</th>
                            #        6 <th scope="col">Severity</th>
                            #        7 <th scope="col">Service Name</th>
                            #        8 <th scope="col">Resource ID</th>
                            #        9 <th scope="col">AI Remediation Advice</th>       
                            #        10 <th scope="col">Source Code References</th>
                            #        11 <th scope="col">Risk</th>
                            # </tr>
                        f"""
                                <tr class="{row_class}">
                                    <td>{resource.metadata.ServiceName}</td> 
                                    <td>{resource.metadata.CheckID.replace("_", "<wbr />_")}</td>
                                    <td>{resource.metadata.CheckTitle}</td>
                                    <td>{resource.region.lower()}</td>
                                    <td>{finding_status}</td>
                                    <td>{resource.metadata.Severity.value}</td>
                                    <td>{resource.metadata.ServiceName}</td>
                                    <td>{resource.resource_uid.replace("<", "&lt;").replace(">", "&gt;").replace("_", "<wbr />_")}</td>
                                    <td>{parse_html_string(unroll_dict(resource.resource_tags))}</td>
                                    <td><p class="show-read-more">{backtoCodeResource}</p></td>
                                    <td><p class="show-read-more">{html.escape(resource.metadata.Risk)}</p></td>
                                </tr>
                                """
                            
                        )

        except Exception as error:
            logger.error(
                f"Errors in Back2Code output. Do not rely on results without confirming this error. report goto.prowler.com/slack \n Error is: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def improve_terraform(self, terraform_file_globs: str, failed_finding_description: str) -> str:
        """
        DESCRIBE ME
        """
        # Create a prompt to ask OpenAI for suggestions
        prompt = f"""
        I have the following Terraform configuration file content. Please suggest a solution for fixing ONLY the following, singular security issue:
        {failed_finding_description}.

        Terraform Configuration File Content:
        ```
        {terraform_file_globs}
        ```

        Can you provide a revised version and explain the changes?
        """

        # Use the OpenAI GPT model to generate a response
        response = openai.chat.completions.create(
            model="chatgpt-4o-latest",
            messages= [
                {
                    "role": "system",
                    "content": "You are a Terraform expert, your output should be in HTML format including a diff for code changes, with the largest header font used being H3."
                },
                {
                    "role": "user",
                    "content": prompt
                }
                ],
            max_tokens=2000,
            temperature=0.7
        )

        # Extract the improved Terraform code and explanation
        improved_output = response.choices[0].message.content
        return improved_output

    @staticmethod
    def finder_public_scm_runner(self, tags: dict) -> dict:

        # Try to complete missing information from tags into a usable GitHub API request for the code within the commit.
        # We need: 
        # - The repository name.
        # - The organization name.
        # - The commit hash.


        # Unpack what we know into ScmFinderMetadata.
        scmFinderMetadata = ScmFinderMetadata(**tags)
        filesFromCommit = []

        if scmFinderMetadata.git_commit is None:
        #NOT IMPLIMENTED YET
            # We're working off a yor_trace
            # We may find a code resource, not a specific commit.
            # TODO: work on yor trace after we have a working commit+repo+org finder.
            return None
        
        if scmFinderMetadata.git_commit is not None:
            # Do we have org and repo to query the GitHub API for the code?
                if scmFinderMetadata.git_org is not None and scmFinderMetadata.git_repo is not None:
                    # We have enough information to query the GitHub API.
                    # We can now find the code.
                    # Check the cache first.
                    cacheHash = hash_sha512(f"{scmFinderMetadata.git_org}{scmFinderMetadata.git_repo}{scmFinderMetadata.git_commit}")
                    cacheResult = scmFinderLookupCache.cacheLookup(cacheHash)
                    if cacheResult is not None:
                        logger.info(f"Cache hit for {scmFinderMetadata.git_org}/{scmFinderMetadata.git_repo}@{scmFinderMetadata.git_commit}")
                        return cacheResult
                    else:
                        logger.info(f"Cache miss for {scmFinderMetadata.git_org}/{scmFinderMetadata.git_repo}@{scmFinderMetadata.git_commit}")
                        filesFromCommit = self.finder_public_scm_github(scmFinderMetadata)
                        scmFinderLookupCache.cacheWrite(cacheHash, filesFromCommit)
                        return filesFromCommit
                
        return None


 
    @staticmethod
    def finder_public_scm_github(scmFinderMetadata) -> dict:

        #Unpacking these to make the code more readable for the requests.get calls.
        
        REPO_OWNER = scmFinderMetadata.git_org
        REPO_NAME = scmFinderMetadata.git_repo
        COMMIT_HASH = scmFinderMetadata.git_commit
        GITHUB_TOKEN = getenv("GITHUB_TOKEN") # Optional: For private repos or higher rate limits

        # GitHub API URL for the specific commit
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits/{COMMIT_HASH}"

        headers = {
            "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else None
        }

        # Make the request to GitHub API
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            commit_data = response.json()
            
            # Normalize gitHub return data so that we can support GitLab or other SCAs in the future.
            # Different init's for different SCAs in the ScmFinderFoundSourceCodeFile class
            files = ScmFinderFoundSourceCodeCollection.github_normalize(commit_data, scmFinderMetadata)
        
        else:
            print(f"Failed to fetch commit. Status code: {response.status_code}")
            print(response.json())

        return files if files else None


class ScmFinderMetadata(BaseModel):
    """
    Class representing metadata we will need to find code in public SCM repositories.

    Attributes:
        - git_org (str): The organization name of the repository.
        - git_repo (str): The repository name.
        - git_commit (str): The commit hash.
        - yor_trace (str): The Yor trace.
        - yor_name (str): The name of the Terraform/IaC object to which the tags/commit hash belongs, by name.
    """

    git_org: str = None
    git_repo: str = None
    git_commit: str = None
    yor_trace: str = None
    yor_name: str = None

class ScmFinderFoundSourceCodeFile(BaseModel):
    fileNameWithPath: str = None
    fileRawURL: str = None
    fileHash: str = None
    fileRawContent: str = None
    fileCommitDiff: str = None

class ScmFinderFoundSourceCodeCollection(BaseModel):
    """
    Class representing data found from source control management SaaS sites for a given finding.
    Used to normalize data returned via different API's from potentially different SaaS solutions (Ie, Github, Gitlab, Bitbucket, etc).
    """

    git_commit: str = None
    commit_msg: str = None
    git_repo: str = None
    git_org: str = None
    files: list[ScmFinderFoundSourceCodeFile] = []
    scmSourceName: str = None
    cacheHash: str = None #Hash of repo/org/comit for cacheing results from SCA's.

    def github_normalize(dict, scmFinderMetadata):
        # Normalize GitHub data into ScmFinderFoundSourceCodeCollection
        scmFinderFoundSourceCodeCollection = ScmFinderFoundSourceCodeCollection()
        scmFinderFoundSourceCodeCollection.git_commit = dict["sha"]
        scmFinderFoundSourceCodeCollection.commit_msg = dict["commit"]["message"]
        scmFinderFoundSourceCodeCollection.git_repo = scmFinderMetadata.git_repo
        scmFinderFoundSourceCodeCollection.git_org = scmFinderMetadata.git_org
        scmFinderFoundSourceCodeCollection.scmSourceName = "github.com"
        for file in dict["files"]:
            scmFinderFoundSourceCodeFile = ScmFinderFoundSourceCodeFile()
            scmFinderFoundSourceCodeFile.fileNameWithPath = file["filename"]
            scmFinderFoundSourceCodeFile.fileRawURL = file["raw_url"]
            #TODO Error handling. API Limits will cause checks not to be reported back upwards as we're still in try/except.
            scmFinderFoundSourceCodeFile.fileRawContent = requests.get(file["raw_url"]).text
            scmFinderFoundSourceCodeFile.fileCommitDiff = file["patch"]
            scmFinderFoundSourceCodeFile.fileHash = file["sha"]
            scmFinderFoundSourceCodeCollection.files.append(scmFinderFoundSourceCodeFile)
        return scmFinderFoundSourceCodeCollection

     
class ScmFinderLookupCache(BaseModel):
    """
    Class used to store and retrieve SCM data from the cache.
    Takes a hash of the SCM provider, repo, org and commit hash as a key.
    Responds with the Object if already stored.
    Returns a cache miss if not.
    """
    cache: dict[str, ScmFinderFoundSourceCodeCollection] = {}

    def cacheLookup(self, hash: str):
        if hash in self.cache:
            return self.cache[hash]
        else:
            return None
      
    def cacheWrite(self, hash: str, data: ScmFinderFoundSourceCodeCollection):
        self.cache[hash] = data
        return data
    

    