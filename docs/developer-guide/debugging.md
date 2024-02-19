# Debugging

Debugging in Prowler make things easier!
If you are developing Prowler, it's possible that you will encounter some situations where you have to inspect the code in depth to fix some unexpected issues during the execution. To do that, if you are using VSCode you can run the code using the integrated debugger. Please, refer to this [documentation](https://code.visualstudio.com/docs/editor/debugging) for guidance about the debugger in VSCode.
The following file is an example of the [debugging configuration](https://code.visualstudio.com/docs/editor/debugging#_launch-configurations) file that you can add to [Virtual Studio Code](https://code.visualstudio.com/).

This file should inside the *.vscode* folder and its name has to be *launch.json*:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Current File",
            "type": "python",
            "request": "launch",
            "program": "prowler.py",
            "args": [
                "aws",
                "-f",
                "eu-west-1",
                "--service",
                "cloudwatch",
                "--log-level",
                "ERROR",
                "-p",
                "dev",
            ],
            "console": "integratedTerminal",
            "justMyCode": false
        },
        {
            "name": "Python: Debug Tests",
            "type": "python",
            "request": "launch",
            "program": "${file}",
            "purpose": [
                "debug-test"
            ],
            "console": "integratedTerminal",
            "justMyCode": false
        }
    ]
}
```
