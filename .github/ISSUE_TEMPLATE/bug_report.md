---
name: Bug report
about: Create a report to help us improve
title: "[Bug]: "
labels: bug, status/needs-triage
assignees: ''

---

<!--
Please use this template to create your bug report. By providing as much info as possible you help us understand the issue, reproduce it and resolve it for you quicker. Therefore, take a couple of extra minutes to make sure you have provided all info needed.

PROTIP: record your screen and attach it as a gif to showcase the issue.

- How to record and attach gif: https://bit.ly/2Mi8T6K
-->

**What happened?**
A clear and concise description of what the bug is or what is not working as expected


**How to reproduce it**
Steps to reproduce the behavior:
1. What command are you running?
2. Cloud provider you are launching
3. Environment you have like single account, multi-account, organizations, multi or single subsctiption, etc.
4. See error


**Expected behavior**
A clear and concise description of what you expected to happen.


**Screenshots or Logs**
If applicable, add screenshots to help explain your problem.
Also, you can add logs (anonymize them first!). Here a command that may help to share a log
`prowler <your arguments> --log-level DEBUG --log-file $(date +%F)_debug.log` then attach here the log file.


**From where are you running Prowler?**
Please, complete the following information:
 - Resource: (e.g. EC2 instance, Fargate task, Docker container manually, EKS, Cloud9, CodeBuild, workstation, etc.)
 - OS: [e.g. Amazon Linux 2, Mac, Alpine, Windows, etc. ]
 - Prowler Version [`prowler --version`]:
 - Python version [`python --version`]:
 - Pip version [`pip --version`]:
 - Installation method (Are you running it from pip package or cloning the github repo?):
 - Others:


**Additional context**
Add any other context about the problem here.
