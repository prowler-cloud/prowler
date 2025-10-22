# Prowler Multicloud CIS Benchmarks PowerBI Template
![Prowler Report](https://github.com/user-attachments/assets/560f7f83-1616-4836-811a-16963223c72f)

## Getting Started

1. Install Microsoft PowerBI Desktop

   This report requires the Microsoft PowerBI Desktop software which can be downloaded for free from Microsoft.
2. Run compliance scans in Prowler

   The report uses compliance csv outputs from Prowler. Compliance scans be run using either [Prowler CLI](https://docs.prowler.com/projects/prowler-open-source/en/latest/#prowler-cli) or [Prowler Cloud/App](https://cloud.prowler.com/sign-in)
   1. Prowler CLI -&gt; Run a Prowler scan using the --compliance option
   2. Prowler Cloud/App -&gt; Navigate to the compliance section to download csv outputs
![Download Compliance Scan](https://github.com/user-attachments/assets/42c11a60-8ce8-4c60-a663-2371199c052b)
   

   The template supports the following CIS Benchmarks only:

   | Compliance Framework                           | Version |
   | ---------------------------------------------- | ------- |
   | CIS Amazon Web Services Foundations Benchmark  | v4.0.1  |
   | CIS Google Cloud Platform Foundation Benchmark | v3.0.0  |
   | CIS Microsoft Azure Foundations Benchmark      | v3.0.0  |
   | CIS Kubernetes Benchmark                       | v1.10.0 |

   Ensure you run or download the correct benchmark versions.
3. Create a local directory to store Prowler csvoutputs

   Once downloaded, place your csv outputs in a directory on your local machine. If you rename the files, they must maintain the provider in the filename.

   To use time-series capabilities such as "compliance percent over time" you'll need scans from multiple dates.
4. Download and run the PowerBI template file (.pbit)

   Running the .pbit file will open PowerBI Desktop and prompt you for the full filepath to the local directory
5. Enter the full filepath to the directory created in step 3

   Provide the full filepath from the root directory.

   Ensure that the filepath is not wrapped in quotation marks (""). If you use Window's "copy as path" feature, it will automatically include quotation marks.
6. Save the report as a PowerBI file (.pbix)

   Once the filepath is entered, the template will automatically ingest and populate the report. You can then save this file as a new PowerBI report. If you'd like to generate another report, simply re-run the template file (.pbit) from step 4.

## Validation

After setting up your dashboard, you may want to validate the Prowler csv files were ingested correctly. To do this, navigate to the "Configuration" tab.

The "loaded CIS Benchmarks" table shows the supported benchmarks and versions. This is defined by the template file and not editable by the user. All benchmarks will be loaded regardless of which providers you provided csv outputs for.

The "Prowler CSV Folder" shows the path to the local directory you provided.

The "Loaded Prowler Exports" table shows the ingested csv files from the local directory. It will mark files that are treated as the latest assessment with a green checkmark.

![Prowler Validation](https://github.com/user-attachments/assets/a543ca9b-6cbe-4ad1-b32a-d4ac2163d447)

## Report Sections

The PowerBI Report is broken into three main report pages

| Report Page | Description                                                                         |
| ----------- | ----------------------------------------------------------------------------------- |
| Overview    | Provides general CIS Benchmark overview across both AWS, Azure, GCP, and Kubernetes |
| Benchmark   | Provides overview of a single CIS Benchmark                                         |
| Requirement | Drill-through page to view details of a single requirement                          |


### Overview Page

The overview page is a general CIS Benchmark overview across both AWS, Azure, GCP, and Kubernetes.

![image](https://github.com/user-attachments/assets/94164fa9-36a4-4bb9-890d-e9a9a63a3e7d)

The page has the following components:

| Component                                | Description                                                              |
| ---------------------------------------- | ------------------------------------------------------------------------ |
| CIS Benchmark Overview                   | Table with benchmark name, Version, and overall compliance percentage    |
| Provider by Requirement Status           | Bar chart showing benchmark requirements by status by provider           |
| Compliance Percent Heatmap               | Heatmap showing compliance percent by benchmark and profile level        |
| Profile level by Requirement Status      | Bar chart showing requirements by status and profile level               |
| Compliance Percent Over Time by Provider | Line chart showing overall compliance perecentage over time by provider. |

### Benchmark Page

The benchmark page provides an overview of a single CIS Benchmark. You can select the benchmark from the dropdown as well as scope down to specific profile levels or regions.

![image](https://github.com/user-attachments/assets/34498ee8-317b-4b81-b241-c561451d8def)

The page has the following components:

| Component                               | Description                                                                                                                                |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Compliance Percent Heatmap              | Heatmap showing compliance percent by region and profile level                                                                             |
| Benchmark Section by Requirement Status | Bar chart showing benchmark requirements by bennchmark section and status                                                                  |
| Compliance percent Over Time by Region  | Line chart showing overall compliance percentage over time by region                                                                       |
| Benchmark Requirements                  | Table showing requirement section, requirement number, reuqirement title, number of resources tested, status, and number of failing checks |

### Requirement Page

The requirement page is a drill-through page to view details of a single requirement. To populate the requirement page right click on a requiement from the "Benchmark Requirements" table on the benchmark page and select "Drill through" -&gt; "Requirement".

![image](https://github.com/user-attachments/assets/5c9172d9-56fe-4514-b341-7e708863fad6)

The requirement page has the following components:

| Component                                  | Description                                                                       |
| ------------------------------------------ | --------------------------------------------------------------------------------- |
| Title                                      | Title of the requirement                                                          |
| Rationale                                  | Rationale of the requirement                                                      |
| Remediation                                | Remedation guidance for the requirement                                           |
| Region by Check Status                     | Bar chart showing Prowler checks by region and status                             |
| Resource Checks for Benchmark Requirements | Table showing Resource ID, Resource Name, Status, Description, and Prowler Checkl |

## Walkthrough Video
[![image](https://github.com/user-attachments/assets/866642c6-43ac-4aac-83d3-bb625002da0b)](https://www.youtube.com/watch?v=lfKFkTqBxjU)


