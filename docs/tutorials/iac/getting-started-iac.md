# Getting Started with the IaC Provider

Prowler's Infrastructure as Code (IaC) provider enables you to scan local infrastructure code for security and compliance issues using [Checkov](https://www.checkov.io/). This provider supports a wide range of IaC frameworks, allowing you to assess your code before deployment.

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

- The IaC provider scans your local directory (or a specified path) for supported IaC files.
- No cloud credentials or authentication are required.
- Mutelist logic is handled by Checkov, not Prowler.
- Results are output in the same formats as other Prowler providers (CSV, JSON, HTML, etc.).

## Usage

To run Prowler with the IaC provider, use the `iac` argument. You can specify the directory to scan, frameworks to include, and paths to exclude.

### Basic Example

```sh
prowler iac --scan-path ./my-iac-directory
```

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

- The IaC provider does not require cloud authentication.
- It is ideal for CI/CD pipelines and local development environments.
- For more details on supported frameworks and rules, see the [Checkov documentation](https://www.checkov.io/1.Welcome/Quick%20Start.html).
