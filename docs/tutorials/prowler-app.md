# Prowler App

The **Prowler App** is a user-friendly interface for the Prowler CLI, providing a visual dashboard to monitor your cloud security posture. This tutorial will guide you through setting up and using the Prowler App.

After [installing](../index.md#prowler-app-installation) the **Prowler App**, access it at [http://localhost:3000](http://localhost:3000).
You can also access to the auto-generated **Prowler API** documentation at [http://localhost:8080/api/v1/docs](http://localhost:8080/api/v1/docs) to see all the available endpoints, parameters and responses.

???+ note
    If you are a [Prowler Cloud](https://cloud.prowler.com/sign-in) user you can see API docs at [https://api.prowler.com/api/v1/docs](https://api.prowler.com/api/v1/docs)

## **Step 1: Sign Up**
### **Sign up with Email**
To get started, sign up using your email and password:

<img src="../../img/sign-up-button.png" alt="Sign Up Button" width="320"/>
<img src="../../img/sign-up.png" alt="Sign Up" width="285"/>

### **Sign up with Social Login**

If Social Login is enabled, you can sign up using your preferred provider (e.g., Google, GitHub).

???+ note "How Social Login Works"
    - If your email is already registered, you will be logged in, and your social account will be linked.
    - If your email is not registered, a new account will be created using your social account email.

???+ note "Enable Social Login"
    See [how to configure Social Login for Prowler](prowler-app-social-login.md) to enable this feature in your own deployments.

---

## **Step 2: Log In**
Once you’ve signed up, log in with your email and password to start using the Prowler App.

<img src="../../img/log-in.png" alt="Log In" width="350"/>

You will see the Overview page with no data yet, so let's start adding a provider to scan your cloud environment.

---

## **Step 3: Add a Provider**
To run your first scan, you need to add a cloud provider account. Prowler App supports AWS, Azure, GCP, and Kubernetes.

1. Navigate to `Settings > Cloud Providers`.
2. Click `Add Account` to set up a new provider and provide your credentials:

<img src="../../img/add-provider.png" alt="Add Provider" width="700"/>

---

## **Step 4: Configure the Provider**
Choose the provider you want to scan from the following options:

<img src="../../img/select-provider.png" alt="Select a Provider" width="700"/>

Once you’ve selected a provider, you need to provide the Provider UID:

- **AWS**: Enter your AWS Account ID.
- **GCP**: Enter your GCP Project ID.
- **Azure**: Enter your Azure Subscription ID.
- **Kubernetes**: Enter your Kubernetes Cluster context of your kubeconfig file.

Optionally, provide a **Provider Alias** for easier identification. Follow the instructions provided to add your credentials:

---
### **Step 4.1: AWS Credentials**
For AWS, enter your `AWS Account ID` and choose one of the following methods to connect:

#### **Step 4.1.1: IAM Access Keys**
1. Select `Connect via Credentials`.

    <img src="../../img/connect-aws-credentials.png" alt="AWS Credentials" width="350"/>

2. Enter your `Access Key ID`, `Secret Access Key` and optionally a `Session Token`:

    <img src="../../img/aws-credentials.png" alt="AWS Credentials" width="350"/>

#### **Step 4.1.2: IAM Role**
1. Select `Connect assuming IAM Role`.

    <img src="../../img/connect-aws-role.png" alt="AWS Role" width="350"/>

2. Enter the `Role ARN` and any optional field like the AWS Access Keys to assume the role, the `External ID`, the `Role Session Name` or the `Session Duration`:

    <img src="../../img/aws-role.png" alt="AWS Role" width="700"/>

???+ note
    check if your AWS Security Token Service (STS) has the EU (Ireland) endpoint active. If not we will not be able to connect to your AWS account.

    If that is the case your STS configuration may look like this:

    <img src="../../img/sts-configuration.png" alt="AWS Role" width="800"/>

    To solve this issue, please activate the EU (Ireland) STS endpoint.

---

### **Step 4.2: Azure Credentials**
For Azure, Prowler App uses a service principal application to authenticate, for more information about the process of creating and adding permissions to a service principal check this [section](../getting-started/requirements.md#azure). When you finish creating and adding the [Entra](./azure/create-prowler-service-principal.md#assigning-the-proper-permissions) and [Subscription](./azure/subscriptions.md#assign-the-appropriate-permissions-to-the-identity-that-is-going-to-be-assumed-by-prowler) scope permissions to the service principal, enter the `Tenant ID`, `Client ID` and `Client Secret` of the service principal application.

<img src="../../img/azure-credentials.png" alt="Azure Credentials" width="700"/>

---
### **Step 4.3: GCP Credentials**
To connect your GCP Project, you need to use the Application Default Credentials (ADC) returned by the `gcloud` CLI. Here’s how to set up:

1. Run the following command in your terminal to authenticate with GCP:
```bash
gcloud auth application-default login
```
2. Once authenticated, get the `Client ID`, `Client Secret` and `Refresh Token` from `~/.config/gcloud/application_default_credentials`.
3. Paste the `Client ID`, `Client Secret` and `Refresh Token` into the Prowler App.

<img src="../../img/gcp-credentials.png" alt="GCP Credentials" width="700"/>

---
### **Step 4.4: Kubernetes Credentials**
For Kubernetes, Prowler App uses a `kubeconfig` file to authenticate, paste the contents of your `kubeconfig` file into the `Kubeconfig content` field.

By default, the `kubeconfig` file is located at `~/.kube/config`.

<img src="../../img/kubernetes-credentials.png" alt="Kubernetes Credentials" width="700"/>

???+ note
    If you are adding an **EKS**, **GKE**, **AKS** or external cluster, follow these additional steps to ensure proper authentication:

    ** Make sure your cluster allow traffic from the Prowler Cloud IP address `52.48.254.174/32` **

    1. Apply the necessary Kubernetes resources to your EKS, GKE, AKS or external cluster (you can find the files in the [`kubernetes` directory of the Prowler repository](https://github.com/prowler-cloud/prowler/tree/master/kubernetes)):
    ```console
    kubectl apply -f kubernetes/prowler-sa.yaml
    kubectl apply -f kubernetes/prowler-role.yaml
    kubectl apply -f kubernetes/prowler-rolebinding.yaml
    ```

    2. Generate a long-lived token for authentication:
    ```console
    kubectl create token prowler-sa -n prowler-ns --duration=0
    ```
        - **Security Note:** The `--duration=0` option generates a non-expiring token, which may pose a security risk if not managed properly. Users should decide on an appropriate expiration time based on their security policies. If a limited-time token is preferred, set `--duration=<TIME>` (e.g., `--duration=24h`).
        - **Important:** If the token expires, Prowler Cloud will no longer be able to authenticate with the cluster. In this case, you will need to generate a new token and **remove and re-add the provider in Prowler Cloud** with the updated `kubeconfig`.

    3. Update your `kubeconfig` to use the ServiceAccount token:
    ```console
    kubectl config set-credentials prowler-sa --token=<SA_TOKEN>
    kubectl config set-context <CONTEXT_NAME> --user=prowler-sa
    ```
    Replace <SA_TOKEN> with the generated token and <CONTEXT_NAME> with your KubeConfig Context Name of your EKS, GKE or AKS cluster.

    4. Now you can add the modified `kubeconfig` in Prowler Cloud. Then simply test the connection.

---

### **Step 4.5: M365 Credentials**
For M365, Prowler App uses a service principal application with user and password to authenticate, for more information about the requirements needed for this provider check this [section](../getting-started/requirements.md#microsoft-365). Also, the detailed steps of how to add this provider to Prowler Cloud and start using it are [here](./microsoft365/getting-started-m365.md).

<img src="../../img/m365-credentials.png" alt="Prowler Cloud M365 Credentials" width="700"/>

---

## **Step 5: Test Connection**
After adding your credentials of your cloud account, click the `Launch` button to verify that the Prowler App can successfully connect to your provider:

<img src="../../img/test-connection-button.png" alt="Test Connection" width="700"/>


## **Step 6: Scan started**
After successfully adding and testing your credentials, Prowler will start scanning your cloud environment, click on the `Go to Scans` button to see the progress:

<img src="../../img/provider-added.png" alt="Start Now" width="700"/>

???+ note
    Prowler will automatically scan all configured providers every **24 hours**, ensuring your cloud environment stays continuously monitored.
---

## **Step 7: Monitor Scan Progress**
Track the progress of your scan in the `Scans` section:

<img src="../../img/scan-progress.png" alt="Scan Progress" width="700"/>

---

## **Step 8: Analyze the Findings**
While the scan is running, start exploring the findings in these sections:

- **Overview**: High-level summary of the scans. <img src="../../img/overview.png" alt="Overview" width="700"/>
- **Compliance**: Insights into compliance status. <img src="../../img/compliance.png" alt="Compliance" width="700"/>
- **Issues**: Types of issues detected.

<img src="../../img/issues.png" alt="Issues" width="300" style="text-align: center;"/>

- **Browse All Findings**: Detailed list of findings detected, where you can filter by severity, service, and more. <img src="../../img/findings.png" alt="Findings" width="700"/>

To view all `new` findings that have not been seen prior to this scan, click the `Delta` filter and select `new`. To view all `changed` findings that have had a status change (from `PASS` to `FAIL` for example), click the `Delta` filter and select `changed`.

## **Step 9: Download the Outputs**

Once a scan is complete, navigate to the Scan Jobs section to download the output files generated by Prowler:

<img src="../../img/scan_jobs_section.png" alt="Scan Jobs section" width="700"/>

These outputs are bundled into a single .zip archive containing:

- CSV report

- JSON-OSCF formatted results

- HTML report

- A folder with individual compliance reports

???+ note "Note"
    The Download button only becomes active after a scan completes successfully.

<img src="../../img/download_output.png" alt="Download output" width="700"/>

The `zip` file unpacks into a folder named like `prowler-output-<provider_id>-<timestamp>`, which includes all of the above outputs. In the example below, you can see the `.csv`, .`json`, and `.html` reports alongside a subfolder for detailed compliance checks.

<img src="../../img/output_folder.png" alt="Output folder" width="700"/>

???+ note "API Note"
    For more information about the API endpoint used by the UI to download the ZIP archive, refer to: [Prowler API Reference - Download Scan Output](https://api.prowler.com/api/v1/docs#tag/Scan/operation/scans_report_retrieve)

## **Step 10: Download specified compliance report**

Once your scan has finished, you don’t need to grab the entire ZIP—just pull down the specific compliance report you want:

1. Navigate to the **Compliance** section of the UI.

<img src="../../img/compliance_section.png" alt="Compliance section" width="700"/>

2. Find the Framework report you need.

3. Click its **Download** icon to retrieve that report’s CSV file with all the detailed findings.

<img src="../../img/compliance_download.png" alt="Download compliance output" width="700"/>

???+ note "API Note"
    To fetch a single compliance report via API, see the Retrieve compliance report as CSV endpoint in the Prowler API Reference.[Prowler API Reference - Retrieve compliance report as CSV](https://api.prowler.com/api/v1/docs#tag/Scan/operation/scans_compliance_retrieve)
