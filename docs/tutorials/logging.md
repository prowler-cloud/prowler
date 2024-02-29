# Logging

Prowler has a logging feature to be as transparent as possible, so that you can see every action that is being performed whilst the tool is being executing.

## Set Log Level

There are different log levels depending on the logging information that is desired to be displayed:

- **DEBUG**: It will show low-level logs from Python.
- **INFO**: It will show all the API calls that are being invoked by the provider.
- **WARNING**: It will show all resources that are being **muted**.
- **ERROR**: It will show any errors, e.g., not authorized actions.
- **CRITICAL**: The default log level. If a critical log appears, it will **exit** Prowler’s execution.

You can establish the log level of Prowler with `--log-level` option:

```console
prowler <provider> --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
```

???+ note
    By default, Prowler will run with the `CRITICAL` log level, since critical errors will abort the execution.

## Export Logs to File

Prowler allows you to export the logs in json format with the `--log-file` option:

```console
prowler <provider> --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL} --log-file <file_name>.json
```

An example of a log file will be the following:

    {
        "timestamp": "2022-12-01 16:45:56,399",
        "filename": "ec2_service.py:114",
        "level": "ERROR",
        "module": "ec2_service",
        "message": "eu-west-2 -- ClientError[102]: An error occurred (UnauthorizedOperation) when calling the DescribeSecurityGroups operation: You are not authorized to perform this operation."
    }
    {
        "timestamp": "2022-12-01 16:45:56,438",
        "filename": "ec2_service.py:134",
        "level": "ERROR",
        "module": "ec2_service",
        "message": "eu-west-2 -- ClientError[124]: An error occurred (UnauthorizedOperation) when calling the DescribeNetworkAcls operation: You are not authorized to perform this operation."
    }

???+ note
    Each finding is represented as a `json` object.
