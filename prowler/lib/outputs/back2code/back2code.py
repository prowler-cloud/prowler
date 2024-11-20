from json import dump
from os import SEEK_SET, getenv
from typing import Optional
import requests

from pydantic import BaseModel, validator

from prowler.config.config import prowler_version, timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output
from prowler.lib.utils.utils import hash_sha512

import openai


class BACK2CODE(Output):
    """
    ASFF class represents a transformation of findings into AWS Security Finding Format (ASFF).

    This class provides methods to transform a list of findings into the ASFF format required by AWS Security Hub. It includes operations such as generating unique identifiers, formatting timestamps, handling compliance frameworks, and ensuring the status values match the allowed values in ASFF.

    Attributes:
        - _data: A list to store the transformed findings.
        - _file_descriptor: A file descriptor to write to file.

    Methods:
        - transform(findings: list[Finding]) -> None: Transforms a list of findings into ASFF format.
        - batch_write_data_to_file() -> None: Writes the findings data to a file in JSON ASFF format.
        - generate_status(status: str, muted: bool = False) -> str: Generates the ASFF status based on the provided status and muted flag.

    References:
        - AWS Security Hub API Reference: https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Compliance.html
        - AWS Security Finding Format Syntax: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html
    """

    def transform(self, findings: list[Finding]) -> None:
        """
        Transforms a list of findings into AWS Security Finding Format (ASFF).

        This method iterates over the list of findings provided as input and transforms each finding into the ASFF format required by AWS Security Hub. It performs several operations for each finding, including generating unique identifiers, formatting timestamps, handling compliance frameworks, and ensuring the status values match the allowed values in ASFF.

        Parameters:
            - findings (list[Finding]): A list of Finding objects representing the findings to be transformed.

        Returns:
            - None

        Notes:
            - The method skips findings with a status of "MANUAL" as it is not valid in SecurityHub.
            - It generates unique identifiers for each finding based on specific attributes.
            - It formats timestamps in the required ASFF format.
            - It handles compliance frameworks and associated standards for each finding.
            - It ensures that the finding status matches the allowed values in ASFF.

        References:
            - AWS Security Hub API Reference: https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Compliance.html
            - AWS Security Finding Format Syntax: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html
        """

        #No point if we have no OpenAI key currently:

        # Get the API key from the environment variable
        openai_key = getenv("OPENAI_API_KEY")

        if not openai_key:
            raise ValueError("OpenAI API key not found. Please set the OPENAI_API_KEY environment variable.")
                
        try:
            for finding in findings:
                # No point digging for code if the finding is not a failed one.
                if finding.status.value == 'FAIL':
                    filesFromCommit = []
                    # Try to find a maching PUBLIC commit, github.com
                    if finding.resource_tags.__len__() > 0:
                        enough_breadcrumbs = False
                        if "yor_trace" in finding.resource_tags:
                            enough_breadcrumbs = True
                        if "git_commit" in finding.resource_tags:
                            enough_breadcrumbs = True
                        if enough_breadcrumbs:
                                # Only call github&gitlab finder if we have enough breadcrumbs.
                                filesFromCommit = self.finder_public_scm_runner(self, finding.resource_tags)
                        
                    # If we found files from a commit, Output some useful info and have AI try to suggest fixes.
                    if filesFromCommit:
                        terraform_file_globs = ""
                        for file in filesFromCommit.files:
                            if ".tf" in file.fileNameWithPath:
                                terraform_file_globs = terraform_file_globs + file.fileRawContent
                        
                        improved_output = self.improve_terraform(terraform_file_globs, finding.metadata.Description)
                        if improved_output:

                            print(f"AI Generated suggestions for failed finding: {finding.metadata.CheckTitle}")
                            print(f"Prowler located the original code at: {filesFromCommit.git_repo}/{filesFromCommit.git_org} at commit: {filesFromCommit.git_commit} \n ")
                            print(improved_output)
                            print("--------------------------------------------------------------------------------------------------\n")
                            print("--------------------------------------------------------------------------------------------------\n")
                        
                        else:
                            print("No improvements suggested by OpenAI. However, the following source code commits locations may be relevant to permenantly fixing your failed finding!:\n") 



        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def improve_terraform(self, terraform_file_globs: str, failed_finding_description: str) -> str:
        
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
                    "content": "You are a Terraform expert."
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

    def batch_write_data_to_file(self) -> None:
       pass

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
            # TODO: FOCUS ON COMMIT FIRST.
            return None
        
        if scmFinderMetadata.git_commit is not None:
            # Do we have org and repo to query the GitHub API for the code?
                if scmFinderMetadata.git_org is not None and scmFinderMetadata.git_repo is not None:
                    # We have enough information to query the GitHub API.
                    # We can now find the code.
                    filesFromCommit = self.finder_public_scm_github(scmFinderMetadata)
                    return filesFromCommit
                
        return None


 
    @staticmethod
    def finder_public_scm_github(scmFinderMetadata) -> dict:

        #Unpacking these to make the code more readable for the requests.get calls.
        
        REPO_OWNER = scmFinderMetadata.git_org
        REPO_NAME = scmFinderMetadata.git_repo
        COMMIT_HASH = scmFinderMetadata.git_commit
        GITHUB_TOKEN = ""  # Optional: For private repos or higher rate limits

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

            # Access files changed in the commit
            #files = commit_data.get("files", [])
            #for file in files:
            #    filename = file.get("filename")
            #    patch = file.get("patch")  # Contains the diff for the file
            #    #print(f"File: {filename}")
            #    #print(f"Patch:\n{patch}\n")
        
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

    def github_normalize(dict, scmFinderMetadata):
        # Normalize GitHub data into ScmFinderFoundSourceCodeCollection
        scmFinderFoundSourceCodeCollection = ScmFinderFoundSourceCodeCollection()
        scmFinderFoundSourceCodeCollection.git_commit = dict["sha"]
        scmFinderFoundSourceCodeCollection.commit_msg = dict["commit"]["message"]
        scmFinderFoundSourceCodeCollection.git_repo = scmFinderMetadata.git_repo
        scmFinderFoundSourceCodeCollection.git_org = scmFinderMetadata.git_org
        for file in dict["files"]:
            scmFinderFoundSourceCodeFile = ScmFinderFoundSourceCodeFile()
            scmFinderFoundSourceCodeFile.fileNameWithPath = file["filename"]
            scmFinderFoundSourceCodeFile.fileRawURL = file["raw_url"]
            scmFinderFoundSourceCodeFile.fileRawContent = requests.get(file["raw_url"]).text
            scmFinderFoundSourceCodeFile.fileCommitDiff = file["patch"]
            scmFinderFoundSourceCodeFile.fileHash = file["sha"]
            scmFinderFoundSourceCodeCollection.files.append(scmFinderFoundSourceCodeFile)
        return scmFinderFoundSourceCodeCollection
    