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

Prowler integration with WAZUH using a python wrapper. Due to the wrapper limitations, this integration can be considered as a proof of concept at this time.

## Features

Wazuh, using a wodle, runs Prowler every certain time and stores alerts (failed checks) using JSON output which Wazuh processes and sends to Elastic Search to be queried from Kibana.

## Requirements

1. Latest AWS-CLI client (`pip install awscli`). If you have it already installed, make sure you are using the latest version, upgrade it: `pip install awscli --upgrade`.
2. Also `jq` is needed (`pip install jq`).

Remember, you must have AWS-CLI credentials already configured in the same instance running Wazuh (run `aws configure` if needed). In this DRAFT I'm using `/root/.aws/credentials` file with [default] as AWS-CLI profile and access keys but you can use assume role configuration as well. For the moment instance profile is not supported in this wrapper.

It may work in previous versions of Wazuh, but this document and integration was tested on Wazuh 3.7.1. So to have a Wazuh running installation is obviously required.

## Integration steps

Add Prowler to Wazuh's integrations:
```
cd /var/ossec/integrations/
git clone https://github.com/toniblyx/prowler
```
Copy `prowler-wrapper.py` to integrations folder:

```
cp /var/ossec/integrations/prowler/integrations/prowler-wrapper.py /var/ossec/integrations/prowler-wrapper.py
```
Then make sure it is executable:
```
chmod +x /var/ossec/integrations/prowler-wrapper.py
```
Run Prowler wrapper manually to make sure it works fine, use `--debug 1` or `--debug 2`):
```
/var/ossec/integrations/prowler-wrapper.py --aws_profile default --aws_account_alias default --debug 2
```

Copy rules file to its location:

```
cp /var/ossec/integrations/prowler/integrations/prowler_rules.xml /var/ossec/etc/rules/prowler_rules.xml
```

Edit `/var/ossec/etc/ossec.conf` and add the following wodle configuration. Remember that here `timeout 21600 seconds` is 6 hours, just to allow Prowler runs completely in case of a large account. The interval recommended is 1d:
```xml
  <wodle name="command">
    <disabled>no</disabled>
    <tag>aws-prowler: account1</tag>
    <command>/var/ossec/integrations/prowler-wrapper.py --aws_profile default --aws_account_alias default</command>
    <interval>1d</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>no</run_on_start>
    <timeout>21600</timeout>
  </wodle>
```
To check multiple AWS accounts, add a wodle per account.

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

```json
{"prowler":{"Timestamp":"2018-11-29T03:15:50Z","Region":"us-east-1","Profile":"default","Account Number”:”1234567890”,”Control":"[check34] Ensure a log metric filter and alarm exist for IAM policy changes (Scored)","Message":"No CloudWatch group found for CloudTrail events","Status":"Fail","Scored":"Scored","Level":"Level 1","Control ID":"3.4"}, "integration": "prowler"}
```
You must see 3 phases goin on.

To check if there is any error you can enable the debug mode of `modulesd` setting the `wazuh_modules.debug=0` variable to 2 in `/var/ossec/etc/internal_options.conf` file. Restart wazuh-manager and errors should appear in the `/var/ossec/logs/ossec.log` file.

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
