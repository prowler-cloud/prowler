# Threat Detection

Prowler allows you to do threat detection in AWS based on the CloudTrail log records. To run checks related with threat detection use:
```
prowler aws --category threat-detection
```
This command will run these checks:

* `cloudtrail_threat_detection_privilege_escalation` -> Detects privilege escalation attacks.
* `cloudtrail_threat_detection_enumeration` -> Detects enumeration attacks.
* `cloudtrail_threat_detection_llm_jacking` -> Detects LLM Jacking attacks.

???+ note
    Threat Detection checks will be only executed using `--category threat-detection` flag due to performance.

## Config File

If you want to manage the behavior of the Threat Detection checks you can edit `config.yaml` file from `/prowler/config`. In this file you can edit the following attributes related with Threat Detection:

* `threat_detection_privilege_escalation_threshold`: determines the percentage of actions found to decide if it is an privilege_scalation attack event, by default is 0.2 (20%)
* `threat_detection_privilege_escalation_minutes`: it is the past minutes to search from now for privilege_escalation attacks, by default is 1440 minutes (24 hours)
* `threat_detection_privilege_escalation_actions`: these are the default actions related with privilege escalation.
* `threat_detection_enumeration_threshold`: determines the percentage of actions found to decide if it is an enumeration attack event, by default is 0.3 (30%)
* `threat_detection_enumeration_minutes`: it is the past minutes to search from now for enumeration attacks, by default is 1440 minutes (24 hours)
* `threat_detection_enumeration_actions`: these are the default actions related with enumeration attacks.
* `threat_detection_llm_jacking_threshold`: determines the percentage of actions found to decide if it is an LLM Jacking attack event, by default is 0.4 (40%)
* `threat_detection_llm_jacking_minutes`: it is the past minutes to search from now for LLM Jacking attacks, by default is 1440 minutes (24 hours)
* `threat_detection_llm_jacking_actions`: these are the default actions related with LLM Jacking attacks.
