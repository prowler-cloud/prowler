# Troubleshooting

- Running `prowler` I get `[File: utils.py:15] [Module: utils]	CRITICAL: path/redacted: OSError[13]`: 

    That is an error related to file descriptors or opened files allowed by your operating system, with `ulimit -n 1000` you solve the issue. We have seen this issue in some macOS Ventura. 


See section [Logging](/tutorials/logging/) for further information or [conctact us](/contact/).