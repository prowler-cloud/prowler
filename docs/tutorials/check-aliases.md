# Check Aliases

Prowler allows you to use aliases for the checks. You only have to add the `CheckAliases` key to the check's metadata with a list of the aliases:
```json title="check.metadata.json"
"Provider": "<provider>",
"CheckID": "<check_id>",
"CheckTitle": "<check_title>",
"CheckAliases": [
  "<check_alias_1>"
  "<check_alias_2>",
  ...
],
...
```
Then, you can execute the check either with its check ID or with one of the previous aliases:
```shell
prowler <provider> -c/--checks <check_alias_1>

Using alias <check_alias_1> for check <check_id>...
```
