# Threat Detection in AWS with Prowler

Prowler enables threat detection in AWS by analyzing CloudTrail log records. To execute threat detection checks, use the following command:

```
prowler aws --category threat-detection
```

This command runs checks to detect:

* \- `cloudtrail_threat_detection_privilege_escalation`: Privilege escalation attacks
* \- `cloudtrail_threat_detection_enumeration`: Enumeration attacks
* \- `cloudtrail_threat_detection_llm_jacking`: LLM Jacking attacks

???+ note
    Threat detection checks are executed only when the `--category threat-detection` flag is used, due to performance considerations.

## Config File for Threat Detection

To manage the behavior of threat detection checks, edit the configuration file located in `config.yaml` file from `/prowler/config`. The following attributes can be modified, all related to threat detection:

* \- `threat_detection_privilege_escalation_threshold`: Defines the percentage of actions required to classify an event as a privilege escalation attack. Default: 0.2 (20%)
* \- `threat_detection_privilege_escalation_minutes`: Specifies the time window (in minutes) to search for privilege escalation attack patterns. Default: 1440 minutes (24 hours).
* `threat_detection_privilege_escalation_actions`: Lists the default actions associated with privilege escalation attacks.
* \- `threat_detection_enumeration_threshold`: Defines the percentage of actions required to classify an event as an enumeration attack. Default: 0.3 (30%)
* \- `threat_detection_enumeration_minutes`: Specifies the time window (in minutes) to search for enumeration attack patterns. Default: 1440 minutes (24 hours).
* \- `threat_detection_enumeration_actions`: Lists the default actions associated with enumeration attacks.
* \- `threat_detection_llm_jacking_threshold`: Defines the percentage of actions required to classify an event as LLM jacking attack. Default: 0.4 (40%)
* \- `threat_detection_llm_jacking_minutes`: Specifies the time window (in minutes) to search for LLM jacking attack patterns. Default: 1440 minutes (24 hours).
* \- `threat_detection_llm_jacking_actions`: Lists the default actions associated with LLM jacking attacks.
Modify these attributes in the configuration file to fine-tune threat detection checks based on your security requirements.
