# Create a new security compliance framework


## Introduction
If you want to create or contribute with your own security frameworks or add public ones to Prowler you need to make sure the checks are available if not you have to create your own. Then create a compliance file per provider like in `prowler/compliance/<provider>/` and name it as `<framework>_<version>_<provider>.json` then follow the following format to create yours.

## Compliance Framework
Each file version of a framework will have the following structure at high level with the case that each framework needs to be generally identified, one requirement can be also called one control but one requirement can be linked to multiple prowler checks.:

- `Framework`: string. Distinguish name of the framework, like CIS
- `Provider`: string. Provider where the framework applies, such as AWS, Azure, OCI,...
- `Version`: string. Version of the framework itself, like 1.4 for CIS.
- `Requirements`: array of objects. Include all requirements or controls with the mapping to Prowler.
- `Requirements_Id`: string. Unique identifier per each requirement in the specific framework
- `Requirements_Description`: string. Description as in the framework.
- `Requirements_Attributes`: array of objects. Includes all needed attributes per each requirement, like levels, sections, etc. Whatever helps to create a dedicated report with the result of the findings. Attributes would be taken as closely as possible from the framework's own terminology directly.
- `Requirements_Checks`: array. Prowler checks that are needed to prove this requirement. It can be one or multiple checks. In case of no automation possible this can be empty.

```
{
  "Framework": "<framework>-<provider>",
  "Version": "<version>",
  "Requirements": [
    {
      "Id": "<unique-id>",
      "Description": "Requirement full description",
      "Checks": [
        "Here is the prowler check or checks that is going to be executed"
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

Finally, to have a proper output file for your reports, your framework data model has to be created in `prowler/lib/outputs/models.py` and also the CLI table output in `prowler/lib/outputs/compliance.py`. Also, you need to add a new conditional in `prowler/lib/outputs/file_descriptors.py` if you create a new CSV model.
