# Compliance
Prowler allows you to execute checks based on requirements defined in compliance frameworks.

## List Available Compliance Frameworks
In order to see which compliance frameworks are cover by Prowler, you can use option `--list-compliance`:
```sh
prowler <provider> --list-compliance
```
Currently, the available frameworks are:

- `cis_1.4_aws`
- `cis_1.5_aws`
- `ens_rd2022_aws`

## List Requirements of Compliance Frameworks
For each compliance framework, you can use option `--list-compliance-requirements` to list its requirements:
```sh
prowler <provider> --list-compliance-requirements <compliance_framework(s)>
```

Example for the first requirements of CIS 1.5 for AWS:

```
Listing CIS 1.5 AWS Compliance Requirements:

Requirement Id: 1.1
	- Description: Maintain current contact details
	- Checks:
 		account_maintain_current_contact_details

Requirement Id: 1.2
	- Description: Ensure security contact information is registered
	- Checks:
 		account_security_contact_information_is_registered

Requirement Id: 1.3
	- Description: Ensure security questions are registered in the AWS account
	- Checks:
 		account_security_questions_are_registered_in_the_aws_account

Requirement Id: 1.4
	- Description: Ensure no 'root' user account access key exists
	- Checks:
 		iam_no_root_access_key

Requirement Id: 1.5
	- Description: Ensure MFA is enabled for the 'root' user account
	- Checks:
 		iam_root_mfa_enabled

[redacted]

```

## Execute Prowler based on Compliance Frameworks
As we mentioned, Prowler can be execute to analyse you environment based on a specific compliance framework, to do it, you can use option `--compliance`:
```sh
prowler <provider> --compliance <compliance_framework>
```
Standard results will be shown and additionally the framework information as the sample below for CIS AWS 1.5. For details a CSV file has been generated as well.

<img src="../img/compliance-cis-sample1.png"/>

## Create and contribute adding other Security Frameworks

If you want to create or contribute with your own security frameworks or add public ones to Prowler you need to make sure the checks are available if not you have to create your own. Then create a compliance file per provider like in `prowler/compliance/aws/` and name it as `<framework>_<version>_<provider>.json` then follow the following format to create yours.

Each file version of a framework will have the following structure at high level with the case that each framework needs to be generally identified), one requirement can be also called one control but one requirement can be linked to multiple prowler checks.:

- `Framework`: string. Indistiguish name of the framework, like CIS
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
      "Description": "Requiemente full description",
      "Checks": [
        "Here is the prowler check or checks that is going to be executed"
      ],
      "Attributes": [
        {
         <Add here your custom attributes.>
        }
      ]
    }
```

Finally, to have a proper output file for your reports, your framework data model has to be created in `prowler/lib/outputs/models.py` and also the CLI table output in `prowler/lib/outputs/compliance.py`.
