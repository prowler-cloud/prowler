# Prowler integration with Wazuh (DRAFT)

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Requirements](#requirements)
- [Integration steps](#integration-steps)
- [Troubleshooting](#troubleshooting)
- [Thanks](#thanks)
- [License](#license)

## Description

Prowler integration is made through syslog. You can send directly to wazuh port 514 , or save in the system logs and wazuh will import.

## Features

We send the logs in format JSON through syslog to the listen port in wazuh.

## Requirements

1. Latest AWS-CLI client (`pip install awscli`). If you have it already installed, make sure you are using the latest version, upgrade it: `pip install awscli --upgrade`.
2. Also `jq` is needed (`pip install jq`).
3. Configure wazuh to listen syslog port(514) through remote module. https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html

Remember, you must have AWS-CLI credentials already configured in the same instance running Wazuh (run `aws configure` if needed). In this DRAFT I'm using `/root/.aws/credentials` file with [default] as AWS-CLI profile and access keys but you can use assume role configuration as well. For the moment instance profile is not supported in this wrapper.

It may work in previous versions of Wazuh, but this document and integration was tested on Wazuh 4.2.X. So to have a Wazuh running installation is obviously required.

## Integration steps


Copy decoder to wazuh decoder folder:

Activate remote module in wazuh, listening in 127.0.0.1 to local prowler execution.

```
git clone https://github.com/toniblyx/prowler

cp prowler/integrations/wazuh/prowler-decoder.xml /var/ossec/etc/decoders/

```
Copy rules to wazuh rules folder:

```
cp prowler/integrations/wazuh/prowler-rules.xml /var/ossec/etc/rules/

```

Execute prowler with your prefered options:

```
prowler -M syslog ......

```

Now restart `wazuh-manager` and look at `/var/ossec/logs/alerts/alerts.json`, eventually you should see FAIL checks detected by Prowler, then you will find them using Kibana. Some Kibana search examples are:

```
data.integration:"prowler" and data.prowler.status:"Fail"
data.integration:"prowler" AND rule.level >= 5
data.integration:"prowler" AND rule.level : 7 or 9
```

Adjust the level range to what alerts you want to include, as alerts, Elastic Search only gets fail messages (7 and 9).

1 - pass
3 - info
5 - error
7 - fail: not scored
9 - fail: scored

## Troubleshooting

To make sure rules are working fine, run `/var/ossec/bin/ossec-logtest` and copy/paste this sample JSON:

```
Nov  3 14:24:00 ip-10-102-132-209 Prowler: {"Profile":"PROFILE","Account Number":"123456789","Control":"[check14] Ensure access keys are rotated every 90 days or less","Message":"FAIL","Severity":"Medium","Status":"us-west-2:","Scored":"","Level":"","Control ID":"1.4","Region":"us-west-2","Timestamp":"2021-11-03T00:24:00Z","Compliance":"ens-op.acc.1.aws.iam.4 ens-op.acc.5.aws.iam.3","Service":"\u001b[1;35miam\u001b[0;39m","CAF Epic":"IAM","Risk":"Access keys consist of an access key ID and secret access key which are used to sign programmatic requests that you make to AWS. AWS users need their own access keys to make programmatic calls to AWS from the AWS Command Line Interface (AWS CLI)- Tools for Windows PowerShell- the AWS SDKs- or direct HTTP calls using the APIs for individual AWS services. It is recommended that all access keys be regularly rotated.","Remediation":"Use the credential report to ensure access_key_X_last_rotated is less than 90 days ago.","Doc link":"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html","Resource ID":"passwd"}

```
You must see 3 phases goin on.

To check if there is any error you can enable the debug mode of `modulesd` setting the `wazuh_modules.debug=0` variable to 2 in `/var/ossec/etc/internal_options.conf` file. Restart wazun-manager and errors should appear in the `/var/ossec/logs/ossec.log` file.

## Thanks

To Jeremy Phillips <jeremy@uranusbytes.com>, who wrote the initial rules file and wrapper and helped me to understand how it works and debug it.

To [Marta Gomez](https://github.com/mgmacias95) and the [Wazuh](https://www.wazuh.com) team for their support to debug this integration and make it work properly. Their job on Wazuh and willingness to help is invaluable.

## License

All CIS based checks in the checks folder are licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International Public License.
The link to the license terms can be found at
<https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode>
Any other piece of code is licensed as Apache License 2.0 as specified in each file. You may obtain a copy of the License at
<http://www.apache.org/licenses/LICENSE-2.0>

NOTE: If you are interested in using Prowler for commercial purposes remember that due to the CC4.0 license “The distributors or partners that are interested and using Prowler would need to enroll as CIS SecureSuite Members to incorporate this product, which includes references to CIS resources, in their offering.". Information about CIS pricing for vendors here: <https://www.cisecurity.org/cis-securesuite/pricing-and-categories/product-vendor/>

**I'm not related anyhow with CIS organization, I just write and maintain Prowler to help companies over the world to make their cloud infrastructure more secure.**

If you want to contact me visit <https://blyx.com/contact>
