# Debugging

Debugging in prowler make things easier!
Here is an example of the debugging configuration file that you can add to vscode to debug prowler:

```json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
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
                // "-M",
                // "html",
                // "-q",
                // "--output-filename",
                // "prowler-pro.html",
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
