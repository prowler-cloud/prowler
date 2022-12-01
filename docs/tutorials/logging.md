# Logging

Prowler has a logging feature to be as transparent as possible so you can see every action that is going on will the tool is been executing.

## Set Log Level

There are different log levels depending on the logging information that is desired to be displayed:

- **DEBUG**: it will show low-level logs of Python.
- **INFO**: it will show all the API Calls that are being used in the provider.
- **WARNING**: it will show the resources that are being **allowlisted**.
- **ERROR**: it will show the errors, e.g., not authorized actions.
- **CRITICAL**: default log level, if a critical log appears, it will **exit** Prowler’s execution.

You can establish the log level of Prowler with `--log-level` option:

```console
prowler <provider> --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
```

> By default, Prowler will run with the `CRITICAL` log level, since critical errors will abort the execution.

## Export Logs to File

Prowler allows you to export the logs in json format with `--log-file` option:

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

> NOTE: Each finding is a `json` object.
