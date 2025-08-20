## Access the App

Go to [http://localhost:3000](http://localhost:3000) after installing the app (see [Quick Start](../index.md#prowler-app-installation)). Sign up with your email and password.

<img src="../img/sign-up-button.png" alt="Sign Up Button" width="320"/>
<img src="../img/sign-up.png" alt="Sign Up" width="285"/>

???+ note "User creation and default tenant behavior"

    When creating a new user, the behavior depends on whether an invitation is provided:

    - **Without an invitation**:

        - A new tenant is automatically created.
        - The new user is assigned to this tenant.
        - A set of **RBAC admin permissions** is generated and assigned to the user for the newly-created tenant.

    - **With an invitation**: The user is added to the specified tenant with the permissions defined in the invitation.

    This mechanism ensures that the first user in a newly created tenant has administrative permissions within that tenant.

## Log In

Log in using your **email and password** to access the Prowler App.

<img src="../img/log-in.png" alt="Log In" width="285"/>

## Add a Cloud Provider

To configure a cloud provider for scanning:

1. Navigate to `Settings > Cloud Providers` and click `Add Account`.
2. Select the cloud provider you wish to scan (**AWS, GCP, Azure, Kubernetes**).
3. Enter the provider's identifier (Optional: Add an alias):
    - **AWS**: Account ID
    - **GCP**: Project ID
    - **Azure**: Subscription ID
    - **Kubernetes**: Cluster ID
    - **M36**: Domain ID
4. Follow the guided instructions to add and authenticate your credentials.

## Start a Scan

Once credentials are successfully added and validated, Prowler initiates a scan of your cloud environment.

Click `Go to Scans` to monitor progress.

## View Results

While the scan is running, you can review findings in the following sections:

- **Overview** – Provides a high-level summary of your scans.
  <img src="../img/overview.png" alt="Overview" width="700"/>

- **Compliance** – Displays compliance insights based on security frameworks.
  <img src="../img/compliance.png" alt="Compliance" width="700"/>

> For detailed usage instructions, refer to the [Prowler App Guide](../tutorials/prowler-app.md).

???+ note
    Prowler will automatically scan all configured providers every **24 hours**, ensuring your cloud environment stays continuously monitored.
