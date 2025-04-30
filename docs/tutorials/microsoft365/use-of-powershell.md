PowerShell is required by this provider because it is the only way to retrieve data from certain Microsoft 365 services.

## Installing PowerShell

If you are using Prowler Cloud, you don't need to worry about PowerShell — it is already installed in our infrastructure.
However, if you want to run Prowler on your own, you must have PowerShell installed to execute the full M365 provider and retrieve all findings.
To learn more about how to install PowerShell and which versions are supported, click [here](../../getting-started/requirements.md#supported-powershell-versions).

## Required Modules

The necessary modules will not be installed automatically by Prowler. Nevertheless, if you want Prowler to install them for you, you can execute the provider with the flag `--init-modules`, which will run the script to install and import them.
If you want to learn more about this process or you are running some issues with this, click [here](../../getting-started/requirements.md#needed-powershell-modules).
