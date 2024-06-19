# Debugging

Debugging in Prowler make things easier!
If you are developing Prowler, it's possible that you will encounter some situations where you have to inspect the code in depth to fix some unexpected issues during the execution.

## VSCode

In VSCode you can run the code using the integrated debugger. Please, refer to this [documentation](https://code.visualstudio.com/docs/editor/debugging) for guidance about the debugger in VSCode.
The following file is an example of the [debugging configuration](https://code.visualstudio.com/docs/editor/debugging#_launch-configurations) file that you can add to [Virtual Studio Code](https://code.visualstudio.com/).

This file should inside the *.vscode* folder and its name has to be *launch.json*:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug AWS Check",
            "type": "debugpy",
            "request": "launch",
            "program": "prowler.py",
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
            "program": "prowler.py",
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
            "program": "prowler.py",
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
            "program": "prowler.py",
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
