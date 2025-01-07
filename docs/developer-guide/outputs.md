# Create a Custom Output Format

## Introduction

Prowler can generate outputs in multiple formats, allowing users to customize the way findings are presented. This is particularly useful when integrating Prowler with third-party tools, creating specialized reports, or simply tailoring the data to meet specific requirements. A custom output format gives you the flexibility to extract and display only the most relevant information in the way you need it.

## Steps to Create a Custom Output Format

### Understand Prowler’s Output Framework

* Prowler organizes its outputs in the /lib/outputs directory. Each format (e.g., JSON, CSV, HTML) is implemented as a Python class.
* Outputs are generated based on findings collected during a scan. Each finding is represented as a structured dictionary containing details like resource IDs, severities, descriptions, and more.
