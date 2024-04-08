# Dashboard
Prowler allows you to run your own local dashboards using the csv outputs provided by Prowler

```sh
prowler dashboard
```

To run Prowler local dashboard with docker, use:

```sh
docker run toniblyx/prowler:latest dashboard
```

The banner and additional info about the dashboard will be shown on your console:
<img src="../img/dashboard/dashboard-banner.png">

## Overview Page

The overview page provides a full impression of your findings obtained from Prowler:

<img src="../img/dashboard/dashboard-overview.png">

In this page you can do multiple functions:
* Apply filters (Assessment Date / Account / Region)
* See wich files has been scaned to generate the dashboard placing your mouse on the `?` icon:
    <img src="../img/dashboard/dashboard-files-scanned.png">
* Download the `Top 25 Failed Findings by Severity` table using the button `DOWNLOAD THIS TABLE AS CSV`

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

If you are a Prowler Saas customer and you want to use your data from your S3 bucket, you can run:

```sh
aws s3 cp s3://<your-bucket>/output/csv ./output --recursive
```
to load the dashboard with the new files.

## Output Path

Prowler will use the outputs from the folder `/output` (for common prowler outputs) and `/output/compliance` (for prowler compliance outputs) to generate the dashboard.

To change the path modify the values `folder_path_overview` or `folder_path_compliance` from `/dashboard/config.py`

## Output Support

Prowler dashboard supports the detailed outputs:

| Provider | V3 | V4 | COMPLIANCE-V3 | COMPLIANCE-V4|
|---|---|---|---|---|
| AWS | ✅ | ✅ | ✅ | ✅ |
| Azure | ❌ | ✅ | ❌ | ✅ |
| Kubernetes | ❌ | ✅ | ❌ | ✅ |
| GCP | ❌ | ✅ | ❌ | ✅ |
