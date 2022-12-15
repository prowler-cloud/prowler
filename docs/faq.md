# FAQ
- <strong>I am getting `OSError` related with `Too many open files`, what can I do?</strong>

In case of a bad connection, high API response times can be given, so they will generate problems because of having several simultaneous connections, to solve this problem in your system, use the command ulimit to increase the simultaneous open files:
```
ulimit -n 30000
```
