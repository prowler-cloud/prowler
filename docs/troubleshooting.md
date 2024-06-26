# Troubleshooting

- **Running `prowler` I get `[File: utils.py:15] [Module: utils]	CRITICAL: path/redacted: OSError[13]`**:

    That is an error related to file descriptors or opened files allowed by your operating system.

    In macOS Ventura, the default value for the `file descriptors` is `256`. With the following command `ulimit -n 1000` you'll increase that value and solve the issue.

    If you have a different OS and you are experiencing the same, please increase the value of your `file descriptors`. You can check it running `ulimit -a | grep "file descriptors"`.

    This error is also related with a lack of system requirements. To improve performance, Prowler stores information in memory so it may need to be run in a system with more than 1GB of memory.


See section [Logging](./tutorials/logging.md) for further information or [contact us](./contact.md).
