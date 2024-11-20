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

    """

    def transform(self, findings: list[Finding]) -> None:
        """
  
        """

        #No point if we have no OpenAI key currently - Although this may change so we can just give Source Repo file pointers and have AI suggestions optional.
        # Get the API key from the environment variable
        openai_key = getenv("OPENAI_API_KEY")

        if not openai_key:
            raise ValueError("OpenAI API key not found. Please set the OPENAI_API_KEY environment variable.")

        # It makes no sense to delay while openAI writes fixes for the same check potentially hundreds of times,
        # Our output for this module will be cleaner and quicker if we sort by Check and Resource.
        # Do this while we're looping through our failed findings anyway.
        findingsByResource = {}
        findingsByCheck = {} 
        
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
                                # If we found files from a commit, append to the finding so we can sort|filter|group|uniqie for our AI recommendations
                                # otherwise we churn generating the same recommendations for potentially multiple resources.
                                finding.back2code = filesFromCommit

                # Sort findings by check and Resource
                                
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
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        # Now we have our findings sorted by check and resource, we can loop through and generate our AI suggestions.
        ## TEMP - Display Unique Failed checks and resources 
        for check in findingsByCheck:
             print(f"Check: {check}")
             for resource in findingsByCheck[check]:
                 print(f">> Resource: {resource.resource_uid}.")
        for resource in findingsByResource:
             print(f"Resource: {resource}") 
             for check in findingsByResource[resource]:
                 print(f">> Check: { check.metadata.CheckID}")
                 if check.back2code is not None:
                    print(f">>>> Infrastructure as Code available! {check.back2code.scmSourceName}::{check.back2code.git_repo}/{check.back2code.git_org}@{check.back2code.git_commit}")
                 else:
                     pass



        # if filesFromCommit:
        #     terraform_file_globs = ""
        #     for file in filesFromCommit.files:
        #         if ".tf" in file.fileNameWithPath:
        #             terraform_file_globs = terraform_file_globs + file.fileRawContent
            
        #     #improved_output = self.improve_terraform(terraform_file_globs, finding.metadata.Description)
        #     improved_output = None
        #     if improved_output:

        #         print(f"AI Generated suggestions for failed finding: {finding.metadata.CheckTitle}")
        #         print(f"Prowler located the original code at: {filesFromCommit.scmSourceName}, repository: {filesFromCommit.git_repo}/{filesFromCommit.git_org},  commit: {filesFromCommit.git_commit} \n ")
        #         print(improved_output)
        #         print("--------------------------------------------------------------------------------------------------\n")
        #         print("--------------------------------------------------------------------------------------------------\n")
            
        #     else:
        #         print("No improvements suggested by OpenAI. However, the following source code commits locations may be relevant to permenantly fixing your failed finding!:\n") 
        #         print(f"Prowler located the original code at: {filesFromCommit.scmSourceName}, repository: {filesFromCommit.git_repo}/{filesFromCommit.git_org},  commit: {filesFromCommit.git_commit} \n ")

      
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
    scmSourceName: str = None

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
    