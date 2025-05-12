# Debugging in Prowler

Debugging in Prowler simplifies the development process, allowing developers to efficiently inspect and resolve unexpected issues during execution.

## Debugging with Visual Studio Code

Visual Studio Code (also referred to as VSCode) provides an integrated debugger for executing and analyzing Prowler code. Refer to the official VSCode debugger [documentation](https://code.visualstudio.com/docs/editor/debugging) for detailed instructions.

Debugging Configuration Example  

The following file is an example of a [debugging configuration](https://code.visualstudio.com/docs/editor/debugging#_launch-configurations) file for [Virtual Studio Code](https://code.visualstudio.com/).

This file must be placed inside the *.vscode* directory and named *launch.json*:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug AWS Check",
            "type": "debugpy",
            "request": "launch",
            "program": "prowler-cli.py",
            "args": [
                "aws",
                "--log-level",
                "ERROR",
                "-c",
                "<check_name>"
            ],
            "console": "integratedTerminal",
            "justMyCode": false
        },
        {
            "name": "Debug Azure Check",
            "type": "debugpy",
            "request": "launch",
            "program": "prowler-cli.py",
            "args": [
                "azure",
                "--sp-env-auth",
                "--log-level",
                "ERROR",
                "-c",
                "<check_name>"
            ],
            "console": "integratedTerminal",
            "justMyCode": false
        },
        {
            "name": "Debug GCP Check",
            "type": "debugpy",
            "request": "launch",
            "program": "prowler-cli.py",
            "args": [
                "gcp",
                "--log-level",
                "ERROR",
                "-c",
                "<check_name>"
            ],
            "console": "integratedTerminal",
            "justMyCode": false
        },
        {
            "name": "Debug K8s Check",
            "type": "debugpy",
            "request": "launch",
            "program": "prowler-cli.py",
            "args": [
                "kubernetes",
                "--log-level",
                "ERROR",
                "-c",
                "<check_name>"
            ],
            "console": "integratedTerminal",
            "justMyCode": false
        }
    ]
}
```