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
        
        try:
            for finding in findings:
                # No point digging for code if the finding is not a failed one.
                if finding.status.value == 'FAIL':
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

        for check in findingsByCheck:
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
                                        print(f"Prowler located the original code at: {filesFromCommit.scmSourceName}, repository: {filesFromCommit.git_repo}/{filesFromCommit.git_org},  commit: {filesFromCommit.git_commit} \n ")
                                        resource.back2code_aisuggestions = improved_output
                                    else:
                                        #print("No improvements suggested by OpenAI. However, the following source code commits locations may be relevant to permenantly fixing your failed finding!:\n") 
                                        #print(f"Prowler located the original code at: {filesFromCommit.scmSourceName}, repository: {filesFromCommit.git_repo}/{filesFromCommit.git_org},  commit: {filesFromCommit.git_commit} \n ")
                                        continue

                        break  # Skip the rest of the loop after the first if statement. We only need one finding per check to generate AI suggestions for.
            
        # for resource in findingsByResource:
        #      print(f"Resource: {resource}") 
        #      for check in findingsByResource[resource]:
        #          print(f">> Check: { check.metadata.CheckID}")
        #          if check.back2code is not None:
        #             print(f">>>> Infrastructure as Code available! {check.back2code.scmSourceName}::{check.back2code.git_repo}/{check.back2code.git_org}@{check.back2code.git_commit}")
        #          else:
        #              pass



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