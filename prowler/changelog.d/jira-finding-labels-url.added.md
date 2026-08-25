`Jira.send_finding()` returns the created issue key, id and browse URL instead of a boolean, and Jira labels are sanitized (whitespace, control characters, 255-character limit) before being sent
