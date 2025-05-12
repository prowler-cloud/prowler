# Creating a New Security Compliance Framework in Prowler

## Introduction

To create or contribute a custom security framework for Prowler—or to integrate a public framework—you must ensure the necessary checks are available. If they are missing, they must be implemented before proceeding. 

Each framework is defined in a compliance file per provider. The file should follow the structure used in `prowler/compliance/<provider>/` and be named `<framework>_<version>_<provider>.json`. Follow the format below to create your own.

## Compliance Framework

Compliance Framework Structure  

Each compliance framework file consists of structured metadata that identifies the framework and maps security checks to requirements or controls. Please note that a single requirement can be linked to multiple Prowler checks:

- `Framework`: string – The distinguished name of the framework (e.g., CIS).
- `Provider`: string – The cloud provider where the framework applies (AWS, Azure, OCI).
- `Version`: string – The framework version (e.g., 1.4 for CIS).
- `Requirements`: array of objects. – Defines security requirements and their mapping to Prowler checks. All requirements or controls are to be included with the mapping to Prowler.
- `Requirements_Id`: string – A unique identifier for each requirement within the framework
- `Requirements_Description`: string – The requirement description as specified in the framework.
- `Requirements_Attributes`: array of objects. – Contains relevant metadata such as security levels, sections, and any additional data needed for reporting with the result of the findings. Attributes should be derived directly from the framework’s own terminology, ensuring consistency with its established definitions.
- `Requirements_Checks`: array. The Prowler checks that are needed to prove this requirement. It can be one or multiple checks. In case automation is not feasible, this can be empty.

```
{
  "Framework": "<framework>-<provider>",
  "Version": "<version>",
  "Requirements": [
    {
      "Id": "<unique-id>",
      "Description": "Full description of the requirement",
      "Checks": [
        "Here is the prowler check or checks that will be executed"
      ],
      "Attributes": [
        {
         <Add here your custom attributes.>
        }
      ]
    },
    ...
  ]
}
```

Finally, to have a proper output file for your reports, your framework data model has to be created in `prowler/lib/outputs/models.py` and also the CLI table output in `prowler/lib/outputs/compliance.py`. Also, you need to add a new conditional in `prowler/lib/outputs/file_descriptors.py` if creating a new CSV model.