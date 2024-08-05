# Dashboard
Prowler allows you to run your own local dashboards using the csv outputs provided by Prowler

```sh
prowler dashboard
```
???+ note
    You can expose the `dashboard` server in another address using the `HOST` environment variable.

To run Prowler local dashboard with Docker, use:

```sh
docker run -v /your/local/dir/prowler-output:/home/prowler/output --env HOST=0.0.0.0 --publish 127.0.0.1:11666:11666 toniblyx/prowler:latest dashboard
```

Make sure you update the `/your/local/dir/prowler-output` to match the path that contains your prowler output.

???+ note
    **Remember that the `dashboard` server is not authenticated, if you expose it to the internet, you are running it at your own risk.**

The banner and additional info about the dashboard will be shown on your console:
<img src="../img/dashboard/dashboard-banner.png">

## Overview Page

The overview page provides a full impression of your findings obtained from Prowler:

<img src="../img/dashboard/dashboard-overview.png">

In this page you can do multiple functions:

* Apply filters:
    * Assesment Date
    * Account
    * Region
    * Severity
    * Service
    * Status
* See wich files has been scanned to generate the dashboard placing your mouse on the `?` icon:
    <img src="../img/dashboard/dashboard-files-scanned.png">
* Download the `Top Findings by Severity` table using the button `DOWNLOAD THIS TABLE AS CSV` or `DOWNLOAD THIS TABLE AS XLSX`
* Click on the provider cards to filter by provider.
* On the dropdowns under `Top Findings by Severity` you can apply multiple sorts to see the information, also you will get a detailed view of each finding using the dropdowns:
<img src="../img/dashboard/dropdown.png">


## Compliance Page

This page shows all the info related to the compliance selected, you can apply multiple filters depending on your preferences.

<img src="../img/dashboard/dashboard-compliance.png">

To add your own compliance to compliance page, add a file with the compliance name (using `_` instead of `.`) to the path `/dashboard/compliance`.

In this file use the format present in the others compliance files to create the table. Example for CIS 2.0:
```python
import warnings

from dashboard.common_methods import get_section_containers_cis

warnings.filterwarnings("ignore")


def get_table(data):
    aux = data[
        [
            "REQUIREMENTS_ID",
            "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION",
            "CHECKID",
            "STATUS",
            "REGION",
            "ACCOUNTID",
            "RESOURCEID",
        ]
    ].copy()

    return get_section_containers_cis(
        aux, "REQUIREMENTS_ID", "REQUIREMENTS_ATTRIBUTES_SECTION"
    )

```

## S3 Integration

If you are using Prowler SaaS with the S3 integration or that integration from Prowler Open Source and you want to use your data from your S3 bucket, you can run:

```sh
aws s3 cp s3://<your-bucket>/output/csv ./output --recursive
```
to load the dashboard with the new files.

## Output Path

Prowler will use the outputs from the folder `/output` (for common prowler outputs) and `/output/compliance` (for prowler compliance outputs) to generate the dashboard.

To change the path modify the values `folder_path_overview` or `folder_path_compliance` from `/dashboard/config.py`

???+ note
    If you have any issue related with dashboards, check that the output path where the dashboard is getting the outputs is correct.

## Output Support

Prowler dashboard supports the detailed outputs:

| Provider | V3 | V4 | COMPLIANCE-V3 | COMPLIANCE-V4|
|---|---|---|---|---|
| AWS | ✅ | ✅ | ✅ | ✅ |
| Azure | ❌ | ✅ | ❌ | ✅ |
| Kubernetes | ❌ | ✅ | ❌ | ✅ |
| GCP | ❌ | ✅ | ❌ | ✅ |
