# IaC Authentication in Prowler

Prowler's Infrastructure as Code (IaC) provider enables you to scan local or remote infrastructure code for security and compliance issues using [Trivy](https://trivy.dev/). This provider supports a wide range of IaC frameworks and requires no cloud authentication for local scans.

### Authentication

- For local scans, no authentication is required.
- For remote repository scans, authentication can be provided via:
    - [**GitHub Username and Personal Access Token (PAT)**](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token-classic)
    - [**GitHub OAuth App Token**](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token)
    - [**Git URL**](https://git-scm.com/docs/git-clone#_git_urls)
