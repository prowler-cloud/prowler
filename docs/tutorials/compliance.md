# Compliance
Prowler allows you to execute checks based on different compliance frameworks.

## List Available Compliance Frameworks
In order to see which compliance frameworks are cover by Prowler, you can use option `--list-compliance`:
```sh
prowler --list-compliance
```
Currently, the available frameworks are:

- cis_1.4_aws
- cis_1.5_aws
- ens_rd2022_aws

## List Requirements of Compliance Frameworks
For each compliance framework, you can use option `--list-compliance-requirements` to list its requirements:
```sh
prowler --list-compliance-requirements <compliance_framework(s)>
```

## Execute Prowler based on Compliance Frameworks
As we mentioned, Prowler can be execute to analyse you environment based on a specific compliance framework, to do it, you can use option `--compliance`:
```sh
prowler --compliance <compliance_framework>
```
