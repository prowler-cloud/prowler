# Getting Started with the IaC Provider

Prowler's Infrastructure as Code (IaC) provider enables you to scan local or remote infrastructure code for security and compliance issues using [Checkov](https://www.checkov.io/). This provider supports a wide range of IaC frameworks, allowing you to assess your code before deployment.

## Supported Frameworks

The IaC provider leverages Checkov to support multiple frameworks, including:

- Terraform
- CloudFormation
- Kubernetes
- ARM (Azure Resource Manager)
- Serverless
- Dockerfile
- YAML/JSON (generic IaC)
- Bicep
- Helm
- GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines, CircleCI, Argo Workflows
- Ansible
- Kustomize
- OpenAPI
- SAST, SCA (Software Composition Analysis)

## How It Works

- The IaC provider scans your local directory (or a specified path) for supported IaC files, or scan a remote repository.
- No cloud credentials or authentication are required for local scans.
- For remote repository scans, authentication can be provided via [git URL](https://git-scm.com/docs/git-clone#_git_urls), CLI flags or environment variables.
- Mutelist logic is handled by Checkov, not Prowler.
- Results are output in the same formats as other Prowler providers (CSV, JSON, HTML, etc.).

## Usage

To run Prowler with the IaC provider, use the `iac` argument. You can specify the directory or repository to scan, frameworks to include, and paths to exclude.

### Scan a Local Directory (default)

```sh
prowler iac --scan-path ./my-iac-directory
```

### Scan a Remote GitHub Repository

```sh
prowler iac --scan-repository-url https://github.com/user/repo.git
```

#### Authentication for Remote Private Repositories

You can provide authentication for private repositories using one of the following methods:

- **GitHub Username and Personal Access Token (PAT):**
  ```sh
  prowler iac --scan-repository-url https://github.com/user/repo.git \
    --github-username <username> --personal-access-token <token>
  ```
- **GitHub OAuth App Token:**
  ```sh
  prowler iac --scan-repository-url https://github.com/user/repo.git \
    --oauth-app-token <oauth_token>
  ```
- If not provided via CLI, the following environment variables will be used (in order of precedence):
    - `GITHUB_OAUTH_APP_TOKEN`
    - `GITHUB_USERNAME` and `GITHUB_PERSONAL_ACCESS_TOKEN`
- If neither CLI flags nor environment variables are set, the scan will attempt to clone without authentication or using the provided in the  [git URL](https://git-scm.com/docs/git-clone#_git_urls).

#### Mutually Exclusive Flags
- `--scan-path` and `--scan-repository-url` are mutually exclusive. Only one can be specified at a time.

### Specify Frameworks

Scan only Terraform and Kubernetes files:

```sh
prowler iac --scan-path ./my-iac-directory --frameworks terraform kubernetes
```

### Exclude Paths

```sh
prowler iac --scan-path ./my-iac-directory --exclude-path ./my-iac-directory/test,./my-iac-directory/examples
```

## Output

You can use the standard Prowler output options, for example:

```sh
prowler iac --scan-path ./iac --output-formats csv json html
```

## Notes

- The IaC provider does not require cloud authentication for local scans.
- For remote repository scans, authentication is optional but required for private repos.
- CLI flags override environment variables for authentication.
- It is ideal for CI/CD pipelines and local development environments.
- For more details on supported frameworks and rules, see the [Checkov documentation](https://www.checkov.io/1.Welcome/Quick%20Start.html).
