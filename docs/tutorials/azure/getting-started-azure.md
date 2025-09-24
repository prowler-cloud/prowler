# Getting Started With Azure on Prowler

## Prowler App

<iframe width="560" height="380" src="https://www.youtube-nocookie.com/embed/v1as8vTFlMg" title="Prowler Cloud Onboarding Azure" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen="1"></iframe>
> Walkthrough video onboarding an Azure Subscription using Service Principal.


???+ note "Government Cloud Support"
    Government cloud subscriptions (Azure Government) are not currently supported, but we expect to add support for them in the near future.

### Prerequisites

Before setting up Azure in Prowler App, you need to create a Service Principal with proper permissions.

For detailed instructions on how to create the Service Principal and configure permissions, see [Authentication > Service Principal](./authentication.md#service-principal-application-authentication-recommended).

---

### Step 1: Get the Subscription ID

1. Go to the [Azure Portal](https://portal.azure.com/#home) and search for `Subscriptions`
2. Locate and copy your Subscription ID

    ![Search Subscription](./img/search-subscriptions.png)
    ![Subscriptions Page](./img/get-subscription-id.png)

---

### Step 2: Access Prowler App

1. Navigate to [Prowler Cloud](https://cloud.prowler.com/) or launch [Prowler App](../prowler-app.md)
2. Navigate to `Configuration` > `Cloud Providers`

    ![Cloud Providers Page](../img/cloud-providers-page.png)

3. Click on `Add Cloud Provider`

    ![Add a Cloud Provider](../img/add-cloud-provider.png)

4. Select `Microsoft Azure`

    ![Select Microsoft Azure](./img/select-azure-prowler-cloud.png)

5. Add the Subscription ID and an optional alias, then click `Next`

    ![Add Subscription ID](./img/add-subscription-id.png)

### Step 3: Add Credentials to Prowler App

Having completed the [Service Principal setup from the Authentication guide](./authentication.md#service-principal-application-authentication-recommended):

1. Go to your App Registration overview and copy the `Client ID` and `Tenant ID`

    ![App Overview](./img/app-overview.png)

2. Go to Prowler App and paste:

    - `Client ID`
    - `Tenant ID`
    - `Client Secret` from [earlier](./authentication.md#service-principal-application-authentication-recommended)

    ![Prowler Cloud Azure Credentials](./img/add-credentials-azure-prowler-cloud.png)

3. Click `Next`

    ![Next Detail](./img/click-next-azure.png)

4. Click "Launch Scan"

    ![Launch Scan Azure](./img/launch-scan.png)

---

## Prowler CLI

### Configure Azure Credentials

To authenticate with Azure, Prowler CLI supports multiple authentication methods. Choose the method that best suits your environment.

For detailed authentication setup instructions, see [Authentication](./authentication.md).

**Service Principal (Recommended)**

Set up environment variables:

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXX"
```

Then run:

```console
prowler azure --sp-env-auth
```

**Azure CLI Credentials**

Use stored Azure CLI credentials:

```console
prowler azure --az-cli-auth
```

**Browser Authentication**

Authenticate using your default browser:

```console
prowler azure --browser-auth --tenant-id <tenant-id>
```

**Managed Identity**

When running on Azure resources:

```console
prowler azure --managed-identity-auth
```

### Subscription Selection

To scan a specific Azure subscription:

```console
prowler azure --subscription-ids <subscription-id>
```

