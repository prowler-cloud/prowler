# Threat Detection

Prowler allows you to do threat detection in AWS based on the CloudTrail log records. To run checks related with threat detection use:
```
prowler aws --category threat-detection
```
This comand will run these checks:

* `cloudtrail_threat_detection_privilege_escalation`
* `cloudtrail_threat_detection_enumeration`

???+ note
    Threat Detection checks will be only executed using `--category threat-detection` flag due to preformance.

## Config File

If you want to manage the behavior of the Threat Detection checks you can edit `config.yaml` file from `/prowler/config`. In this file you can edit the following attributes related with Threat Detection:

* `threat_detection_privilege_escalation_threshold`: determines the percentage of actions found to decide if it is an privilege_scalation attack event, by default is 0.1 (10%)
* `threat_detection_privilege_escalation_minutes`: it is the past minutes to search from now for privilege_escalation attacks, by default is 1440 minutes (24 hours)
* `threat_detection_privilege_escalation_actions`: these are the default actions related with priviledge scalation.
* `threat_detection_enumeration_threshold`: determines the percentage of actions found to decide if it is an enumeration attack event, by default is 0.1 (10%)
* `threat_detection_enumeration_minutes`: it is the past minutes to search from now for enumeration attacks, by default is 1440 minutes (24 hours)
* `threat_detection_enumeration_actions`: these are the default actions related with enumeration attacks.
