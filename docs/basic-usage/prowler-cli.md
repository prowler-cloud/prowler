## Running Prowler

Running Prowler requires specifying the provider (e.g `aws`, `gcp`, `azure`, `m365`, `github` or `kubernetes`):

???+ note
    If no provider is specified, AWS is used by default for backward compatibility with Prowler v2.

```console
prowler <provider>
```
![Prowler Execution](../img/short-display.png)

???+ note
    Running the `prowler` command without options will uses environment variable credentials. Refer to the [Requirements](../getting-started/requirements.md) section for credential configuration details.

## Verbose Output

If you prefer the former verbose output, use: `--verbose`. This allows seeing more info while Prowler is running, minimal output is displayed unless verbosity is enabled.

## Report Generation

By default, Prowler generates CSV, JSON-OCSF, and HTML reports. To generate a JSON-ASFF report (used by AWS Security Hub), specify `-M` or `--output-modes`:

```console
prowler <provider> -M csv json-asff json-ocsf html
```
The HTML report is saved in the output directory, alongside other reports. It will look like this:

![Prowler Execution](../img/html-output.png)

## Listing Available Checks and Services

List all available checks or services within a provider using `-l`/`--list-checks` or `--list-services`.

```console
prowler <provider> --list-checks
prowler <provider> --list-services
```
## Running Specific Checks or Services

Execute specific checks or services using `-c`/`checks` or `-s`/`services`:

```console
prowler azure --checks storage_blob_public_access_level_is_disabled
prowler aws --services s3 ec2
prowler gcp --services iam compute
prowler kubernetes --services etcd apiserver
```
## Excluding Checks and Services

Checks and services can be excluded with `-e`/`--excluded-checks` or `--excluded-services`:

```console
prowler aws --excluded-checks s3_bucket_public_access
prowler azure --excluded-services defender iam
prowler gcp --excluded-services kms
prowler kubernetes --excluded-services controllermanager
```
## Additional Options

Explore more advanced time-saving execution methods in the [Miscellaneous](../tutorials/misc.md) section.

Access the help menu and view all available options with `-h`/`--help`:

```console
prowler --help
```

## AWS

Use a custom AWS profile with `-p`/`--profile` and/or specific AWS regions with `-f`/`--filter-region`:

```console
prowler aws --profile custom-profile -f us-east-1 eu-south-2
```

???+ note
    By default, `prowler` will scan all AWS regions.

See more details about AWS Authentication in the [Requirements](../getting-started/requirements.md#aws) section.

## Azure

Azure requires specifying the auth method:

```console
# To use service principal authentication
prowler azure --sp-env-auth

# To use az cli authentication
prowler azure --az-cli-auth

# To use browser authentication
prowler azure --browser-auth --tenant-id "XXXXXXXX"

# To use managed identity auth
prowler azure --managed-identity-auth
```

See more details about Azure Authentication in [Requirements](../getting-started/requirements.md#azure)

By default, Prowler scans all accessible subscriptions. Scan specific subscriptions using the following flag (using az cli auth as example):

```console
prowler azure --az-cli-auth --subscription-ids <subscription ID 1> <subscription ID 2> ... <subscription ID N>
```
## Google Cloud

- **User Account Credentials**

    By default, Prowler uses **User Account credentials**. Configure accounts using:

    - `gcloud init` – Set up a new account.
    - `gcloud config set account <account>` – Switch to an existing account.

    Once configured, obtain access credentials using: `gcloud auth application-default login`.

- **Service Account Authentication**

    Alternatively, you can use Service Account credentials:

    Generate and download Service Account keys in JSON format. Refer to [Google IAM documentation](https://cloud.google.com/iam/docs/creating-managing-service-account-keys) for details.

    Provide the key file location using this argument:

    ```console
    prowler gcp --credentials-file path
    ```

- **Scanning Specific GCP Projects**

    By default, Prowler scans all accessible GCP projects. Scan specific projects with the `--project-ids` flag:

    ```console
    prowler gcp --project-ids <Project ID 1> <Project ID 2> ... <Project ID N>
    ```

- **GCP Retry Configuration**

    Configure the maximum number of retry attempts for Google Cloud SDK API calls with the `--gcp-retries-max-attempts` flag:

    ```console
    prowler gcp --gcp-retries-max-attempts 5
    ```

    This is useful when experiencing quota exceeded errors (HTTP 429) to increase the number of automatic retry attempts.

## Kubernetes

Prowler enables security scanning of Kubernetes clusters, supporting both **in-cluster** and **external** execution.

- **Non In-Cluster Execution**

    ```console
    prowler kubernetes --kubeconfig-file path
    ```
    ???+ note
        If no `--kubeconfig-file` is provided, Prowler will use the default KubeConfig file location (`~/.kube/config`).

- **In-Cluster Execution**

    To run Prowler inside the cluster, apply the provided YAML configuration to deploy a job in a new namespace:

    ```console
    kubectl apply -f kubernetes/prowler-sa.yaml
    kubectl apply -f kubernetes/job.yaml
    kubectl apply -f kubernetes/prowler-role.yaml
    kubectl apply -f kubernetes/prowler-rolebinding.yaml
    kubectl get pods --namespace prowler-ns --> prowler-XXXXX
    kubectl logs prowler-XXXXX --namespace prowler-ns
    ```

    ???+ note
        By default, Prowler scans all namespaces in the active Kubernetes context. Use the `--context`flag to specify the context to be scanned and `--namespaces` to restrict scanning to specific namespaces.

## Microsoft 365

Microsoft 365 requires specifying the auth method:

```console

# To use service principal authentication for MSGraph and PowerShell modules
prowler m365 --sp-env-auth

# To use both service principal (for MSGraph) and user credentials (for PowerShell modules)
prowler m365 --env-auth

# To use az cli authentication
prowler m365 --az-cli-auth

# To use browser authentication
prowler m365 --browser-auth --tenant-id "XXXXXXXX"

```

See more details about M365 Authentication in the [Requirements](../getting-started/requirements.md#microsoft-365) section.

## GitHub

Prowler enables security scanning of your **GitHub account**, including **Repositories**, **Organizations** and **Applications**.

- **Supported Authentication Methods**

    Authenticate using one of the following methods:

    ```console
    # Personal Access Token (PAT):
    prowler github --personal-access-token pat

    # OAuth App Token:
    prowler github --oauth-app-token oauth_token

    # GitHub App Credentials:
    prowler github --github-app-id app_id --github-app-key app_key
    ```

    ???+ note
        If no login method is explicitly provided, Prowler will automatically attempt to authenticate using environment variables in the following order of precedence:

        1. `GITHUB_PERSONAL_ACCESS_TOKEN`
        2. `OAUTH_APP_TOKEN`
        3. `GITHUB_APP_ID` and `GITHUB_APP_KEY`

## Infrastructure as Code (IaC)

Prowler's Infrastructure as Code (IaC) provider enables you to scan local or remote infrastructure code for security and compliance issues using [Checkov](https://www.checkov.io/). This provider supports a wide range of IaC frameworks, allowing you to assess your code before deployment.

```console
# Scan a directory for IaC files
prowler iac --scan-path ./my-iac-directory

# Scan a remote GitHub repository (public or private)
prowler iac --scan-repository-url https://github.com/user/repo.git

# Authenticate to a private repo with GitHub username and PAT
prowler iac --scan-repository-url https://github.com/user/repo.git \
  --github-username <username> --personal-access-token <token>

# Authenticate to a private repo with OAuth App Token
prowler iac --scan-repository-url https://github.com/user/repo.git \
  --oauth-app-token <oauth_token>

# Specify frameworks to scan (default: all)
prowler iac --scan-path ./my-iac-directory --frameworks terraform kubernetes

# Exclude specific paths
prowler iac --scan-path ./my-iac-directory --exclude-path ./my-iac-directory/test,./my-iac-directory/examples
```

???+ note
    - `--scan-path` and `--scan-repository-url` are mutually exclusive; only one can be specified at a time.
    - For remote repository scans, authentication can be provided via CLI flags or environment variables (`GITHUB_OAUTH_APP_TOKEN`, `GITHUB_USERNAME`, `GITHUB_PERSONAL_ACCESS_TOKEN`). CLI flags take precedence.
    - The IaC provider does not require cloud authentication for local scans.
    - It is ideal for CI/CD pipelines and local development environments.
    - For more details on supported frameworks and rules, see the [Checkov documentation](https://www.checkov.io/1.Welcome/Quick%20Start.html)

See more details about IaC scanning in the [IaC Tutorial](../tutorials/iac/getting-started-iac.md) section.
