---
title: "Helm installation"
linkTitle: "Helm installation"
---

# prowler

[prowler](https://github.com/prowler-cloud/prowler)

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 5.3.0](https://img.shields.io/badge/AppVersion-5.3.0-informational?style=flat-square)

## Installation

This is a OCI helm chart, helm started support OCI in version 3.8.0.

```shell
helm upgrade -i prowler oci://ghcr.io/prowler-cloud/helm-charts/prowler --version 5.3.0
```

## Getting started

As described in the documentation, Prowler requiers Valkey and a postgres instance to be deployed in server mode.
This helm chart does not support the deployment of these services.
There are to many ways to configure those resources and we don't want to be in charge of making your postgres intance production ready.

But to easily get started we have included some instructions on how to install the required services in a Kubernetes cluster.
These settings are **NOT** for production.
For production level postgres instance, we recommend looking in to [cloudnative-pg](https://github.com/cloudnative-pg/cloudnative-pg).

### Postgres

```postgres-values.yaml
auth:
    database: prowler_db
    username: prowler
    postgresPassword: postgres
    password: postgres
```

Save this file as `postgres-values.yaml` and run the following command to install the postgres instance.

```shell
helm upgrade -i postgres oci://registry-1.docker.io/bitnamicharts/postgresql --create-namespace --namespace prowler --version 16.4.14 -f postgres-values.yaml
```

### Valkey

In this example we run valkey as a standalone instance, to make it as easy as possible to get started.
Once again, not for production.

```shell
helm upgrade -i valkey oci://registry-1.docker.io/bitnamicharts/valkey -n prowler --version 2.3.0 --set architecture=standalone --set auth.enabled=false
```

### Secrets

You should never write secrets directly in the values file.
How you choose to manage your connection infromation is up to you.
But something like [external-secrets](https://external-secrets.io/latest/) is worth looking in to and store your connection strings in a KMS.
You can create those resources trough the helm chart with "extraObjects".

But to make it easy to try out the helm chart here is a ready secret that matches the above values to connect to the postgres instance.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: prowler-db
  namespace: prowler
type: Opaque
data:
  database: cHJvd2xlcl9kYg==  # prowler_db
  username: cHJvd2xlcg== # prowler
  password: cHJvd2xlcg== # prowler
  postgresPassword: cG9zdGdyZXM= # postgres
```

### Prowler config

On top of the values file you need to add your own custom values.
This is to add secrets infromation that is needed.

[values-example.yaml](values-example.yaml)

To install the helm chart from the repo, run

```shell
helm upgrade -i prowler . -n prowler -f values-example.yaml
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| api.affinity | object | `{}` |  |
| api.image.pullPolicy | string | `""` |  |
| api.image.registry | string | `""` |  |
| api.image.repository | string | `""` |  |
| api.image.tag | string | `""` |  |
| api.nodeSelector | object | `{}` |  |
| api.podAnnotations | object | `{}` |  |
| api.replicaCount | int | `1` |  |
| api.resources | object | `{}` |  |
| api.service.port | int | `8080` |  |
| api.service.type | string | `"ClusterIP"` |  |
| api.serviceAccount.annotations | object | `{}` |  |
| api.serviceAccount.create | bool | `true` |  |
| api.serviceAccount.name | string | `""` |  |
| api.tolerations | list | `[]` |  |
| api.volumeMounts | list | `[]` |  |
| api.volumes | list | `[]` |  |
| appConfig.DJANGO_ACCESS_TOKEN_LIFETIME | string | `"30"` |  |
| appConfig.DJANGO_ALLOWED_HOSTS | string | `"localhost,127.0.0.1,prowler-api"` |  |
| appConfig.DJANGO_BIND_ADDRESS | string | `"0.0.0.0"` |  |
| appConfig.DJANGO_BROKER_VISIBILITY_TIMEOUT | int | `86400` |  |
| appConfig.DJANGO_CACHE_MAX_AGE | string | `"3600"` |  |
| appConfig.DJANGO_DEBUG | bool | `false` |  |
| appConfig.DJANGO_LOGGING_FORMATTER | string | `"human_readable"` |  |
| appConfig.DJANGO_LOGGING_LEVEL | string | `"INFO"` |  |
| appConfig.DJANGO_MANAGE_DB_PARTITIONS | string | `"False"` |  |
| appConfig.DJANGO_PORT | string | `"8080"` |  |
| appConfig.DJANGO_REFRESH_TOKEN_LIFETIME | string | `"1440"` |  |
| appConfig.DJANGO_SETTINGS_MODULE | string | `"config.django.production"` |  |
| appConfig.DJANGO_STALE_WHILE_REVALIDATE | string | `"60"` |  |
| appConfig.DJANGO_WORKERS | int | `2` |  |
| appConfig.VALKEY_DB | string | `"0"` |  |
| appConfig.VALKEY_HOST | string | `"valkey-headless"` |  |
| appConfig.VALKEY_PORT | string | `"6379"` |  |
| celeryBeat.affinity | object | `{}` |  |
| celeryBeat.image.pullPolicy | string | `""` |  |
| celeryBeat.image.registry | string | `""` |  |
| celeryBeat.image.repository | string | `""` |  |
| celeryBeat.image.tag | string | `""` |  |
| celeryBeat.nodeSelector | object | `{}` |  |
| celeryBeat.podAnnotations | object | `{}` |  |
| celeryBeat.replicaCount | int | `1` |  |
| celeryBeat.resources | object | `{}` |  |
| celeryBeat.serviceAccount.annotations | object | `{}` |  |
| celeryBeat.serviceAccount.create | bool | `true` |  |
| celeryBeat.serviceAccount.name | string | `""` |  |
| celeryBeat.tolerations | list | `[]` |  |
| celeryWorker.affinity | object | `{}` |  |
| celeryWorker.image.pullPolicy | string | `""` |  |
| celeryWorker.image.registry | string | `""` |  |
| celeryWorker.image.repository | string | `""` |  |
| celeryWorker.image.tag | string | `""` |  |
| celeryWorker.nodeSelector | object | `{}` |  |
| celeryWorker.podAnnotations | object | `{}` |  |
| celeryWorker.replicaCount | int | `1` |  |
| celeryWorker.resources | object | `{}` |  |
| celeryWorker.serviceAccount.annotations | object | `{}` |  |
| celeryWorker.serviceAccount.create | bool | `true` |  |
| celeryWorker.serviceAccount.name | string | `""` |  |
| celeryWorker.tolerations | list | `[]` |  |
| extraObjects | list | `[]` |  |
| fullnameOverride | string | `""` |  |
| global.pullPolicy | string | `"IfNotPresent"` |  |
| global.registry | string | `"docker.io"` |  |
| global.repository | string | `"prowlercloud/prowler-api"` |  |
| global.tag | string | `""` |  |
| imagePullSecrets | list | `[]` |  |
| ingress.annotations | object | `{}` |  |
| ingress.className | string | `""` |  |
| ingress.enabled | bool | `false` |  |
| ingress.hosts[0].host | string | `"chart-example.local"` |  |
| ingress.hosts[0].paths[0].path | string | `"/"` |  |
| ingress.hosts[0].paths[0].pathType | string | `"ImplementationSpecific"` |  |
| ingress.tls | list | `[]` |  |
| mainConfig.aws.check_rds_instance_replicas | bool | `false` |  |
| mainConfig.aws.days_to_expire_threshold | int | `7` |  |
| mainConfig.aws.ec2_allowed_instance_owners[0] | string | `"amazon-elb"` |  |
| mainConfig.aws.ec2_allowed_interface_types[0] | string | `"api_gateway_managed"` |  |
| mainConfig.aws.ec2_allowed_interface_types[1] | string | `"vpc_endpoint"` |  |
| mainConfig.aws.ec2_high_risk_ports[0] | int | `25` |  |
| mainConfig.aws.ec2_high_risk_ports[10] | int | `8088` |  |
| mainConfig.aws.ec2_high_risk_ports[1] | int | `110` |  |
| mainConfig.aws.ec2_high_risk_ports[2] | int | `135` |  |
| mainConfig.aws.ec2_high_risk_ports[3] | int | `143` |  |
| mainConfig.aws.ec2_high_risk_ports[4] | int | `445` |  |
| mainConfig.aws.ec2_high_risk_ports[5] | int | `3000` |  |
| mainConfig.aws.ec2_high_risk_ports[6] | int | `4333` |  |
| mainConfig.aws.ec2_high_risk_ports[7] | int | `5000` |  |
| mainConfig.aws.ec2_high_risk_ports[8] | int | `5500` |  |
| mainConfig.aws.ec2_high_risk_ports[9] | int | `8080` |  |
| mainConfig.aws.ecr_repository_vulnerability_minimum_severity | string | `"MEDIUM"` |  |
| mainConfig.aws.eks_cluster_oldest_version_supported | string | `"1.28"` |  |
| mainConfig.aws.eks_required_log_types[0] | string | `"api"` |  |
| mainConfig.aws.eks_required_log_types[1] | string | `"audit"` |  |
| mainConfig.aws.eks_required_log_types[2] | string | `"authenticator"` |  |
| mainConfig.aws.eks_required_log_types[3] | string | `"controllerManager"` |  |
| mainConfig.aws.eks_required_log_types[4] | string | `"scheduler"` |  |
| mainConfig.aws.elb_min_azs | int | `2` |  |
| mainConfig.aws.elbv2_min_azs | int | `2` |  |
| mainConfig.aws.excluded_sensitive_environment_variables | list | `[]` |  |
| mainConfig.aws.fargate_linux_latest_version | string | `"1.4.0"` |  |
| mainConfig.aws.fargate_windows_latest_version | string | `"1.0.0"` |  |
| mainConfig.aws.insecure_key_algorithms[0] | string | `"RSA-1024"` |  |
| mainConfig.aws.insecure_key_algorithms[1] | string | `"P-192"` |  |
| mainConfig.aws.insecure_key_algorithms[2] | string | `"SHA-1"` |  |
| mainConfig.aws.lambda_min_azs | int | `2` |  |
| mainConfig.aws.log_group_retention_days | int | `365` |  |
| mainConfig.aws.max_console_access_days | int | `45` |  |
| mainConfig.aws.max_days_secret_unrotated | int | `90` |  |
| mainConfig.aws.max_days_secret_unused | int | `90` |  |
| mainConfig.aws.max_disconnect_timeout_in_seconds | int | `300` |  |
| mainConfig.aws.max_ec2_instance_age_in_days | int | `180` |  |
| mainConfig.aws.max_idle_disconnect_timeout_in_seconds | int | `600` |  |
| mainConfig.aws.max_security_group_rules | int | `50` |  |
| mainConfig.aws.max_session_duration_seconds | int | `36000` |  |
| mainConfig.aws.max_unused_access_keys_days | int | `45` |  |
| mainConfig.aws.min_kinesis_stream_retention_hours | int | `168` |  |
| mainConfig.aws.mute_non_default_regions | bool | `false` |  |
| mainConfig.aws.obsolete_lambda_runtimes[0] | string | `"java8"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[10] | string | `"nodejs8.10"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[11] | string | `"nodejs10.x"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[12] | string | `"nodejs12.x"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[13] | string | `"nodejs14.x"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[14] | string | `"nodejs16.x"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[15] | string | `"dotnet5.0"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[16] | string | `"dotnet7"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[17] | string | `"dotnetcore1.0"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[18] | string | `"dotnetcore2.0"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[19] | string | `"dotnetcore2.1"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[1] | string | `"go1.x"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[20] | string | `"dotnetcore3.1"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[21] | string | `"ruby2.5"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[22] | string | `"ruby2.7"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[2] | string | `"provided"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[3] | string | `"python3.6"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[4] | string | `"python2.7"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[5] | string | `"python3.7"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[6] | string | `"nodejs4.3"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[7] | string | `"nodejs4.3-edge"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[8] | string | `"nodejs6.10"` |  |
| mainConfig.aws.obsolete_lambda_runtimes[9] | string | `"nodejs"` |  |
| mainConfig.aws.organizations_enabled_regions | list | `[]` |  |
| mainConfig.aws.organizations_trusted_delegated_administrators | list | `[]` |  |
| mainConfig.aws.recommended_cdk_bootstrap_version | int | `21` |  |
| mainConfig.aws.secrets_ignore_patterns | list | `[]` |  |
| mainConfig.aws.shodan_api_key | string | `nil` |  |
| mainConfig.aws.threat_detection_enumeration_actions[0] | string | `"DescribeAccessEntry"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[10] | string | `"DescribeInstanceAttribute"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[11] | string | `"DescribeInstanceInformation"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[12] | string | `"DescribeInstanceTypes"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[13] | string | `"DescribeInstances"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[14] | string | `"DescribeInstances"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[15] | string | `"DescribeKeyPairs"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[16] | string | `"DescribeLogGroups"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[17] | string | `"DescribeLogStreams"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[18] | string | `"DescribeOrganization"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[19] | string | `"DescribeRegions"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[1] | string | `"DescribeAccountAttributes"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[20] | string | `"DescribeSecurityGroups"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[21] | string | `"DescribeSnapshotAttribute"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[22] | string | `"DescribeSnapshotTierStatus"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[23] | string | `"DescribeSubscriptionFilters"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[24] | string | `"DescribeTransitGatewayMulticastDomains"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[25] | string | `"DescribeVolumes"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[26] | string | `"DescribeVolumesModifications"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[27] | string | `"DescribeVpcEndpointConnectionNotifications"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[28] | string | `"DescribeVpcs"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[29] | string | `"GetAccount"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[2] | string | `"DescribeAvailabilityZones"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[30] | string | `"GetAccountAuthorizationDetails"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[31] | string | `"GetAccountSendingEnabled"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[32] | string | `"GetBucketAcl"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[33] | string | `"GetBucketLogging"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[34] | string | `"GetBucketPolicy"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[35] | string | `"GetBucketReplication"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[36] | string | `"GetBucketVersioning"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[37] | string | `"GetCallerIdentity"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[38] | string | `"GetCertificate"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[39] | string | `"GetConsoleScreenshot"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[3] | string | `"DescribeBundleTasks"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[40] | string | `"GetCostAndUsage"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[41] | string | `"GetDetector"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[42] | string | `"GetEbsDefaultKmsKeyId"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[43] | string | `"GetEbsEncryptionByDefault"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[44] | string | `"GetFindings"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[45] | string | `"GetFlowLogsIntegrationTemplate"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[46] | string | `"GetIdentityVerificationAttributes"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[47] | string | `"GetInstances"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[48] | string | `"GetIntrospectionSchema"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[49] | string | `"GetLaunchTemplateData"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[4] | string | `"DescribeCarrierGateways"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[50] | string | `"GetLaunchTemplateData"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[51] | string | `"GetLogRecord"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[52] | string | `"GetParameters"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[53] | string | `"GetPolicyVersion"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[54] | string | `"GetPublicAccessBlock"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[55] | string | `"GetQueryResults"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[56] | string | `"GetRegions"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[57] | string | `"GetSMSAttributes"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[58] | string | `"GetSMSSandboxAccountStatus"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[59] | string | `"GetSendQuota"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[5] | string | `"DescribeClientVpnRoutes"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[60] | string | `"GetTransitGatewayRouteTableAssociations"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[61] | string | `"GetUserPolicy"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[62] | string | `"HeadObject"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[63] | string | `"ListAccessKeys"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[64] | string | `"ListAccounts"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[65] | string | `"ListAllMyBuckets"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[66] | string | `"ListAssociatedAccessPolicies"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[67] | string | `"ListAttachedUserPolicies"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[68] | string | `"ListClusters"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[69] | string | `"ListDetectors"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[6] | string | `"DescribeCluster"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[70] | string | `"ListDomains"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[71] | string | `"ListFindings"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[72] | string | `"ListHostedZones"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[73] | string | `"ListIPSets"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[74] | string | `"ListIdentities"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[75] | string | `"ListInstanceProfiles"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[76] | string | `"ListObjects"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[77] | string | `"ListOrganizationalUnitsForParent"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[78] | string | `"ListOriginationNumbers"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[79] | string | `"ListPolicyVersions"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[7] | string | `"DescribeDhcpOptions"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[80] | string | `"ListRoles"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[81] | string | `"ListRoles"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[82] | string | `"ListRules"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[83] | string | `"ListServiceQuotas"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[84] | string | `"ListSubscriptions"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[85] | string | `"ListTargetsByRule"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[86] | string | `"ListTopics"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[87] | string | `"ListUsers"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[88] | string | `"LookupEvents"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[89] | string | `"Search"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[8] | string | `"DescribeFlowLogs"` |  |
| mainConfig.aws.threat_detection_enumeration_actions[9] | string | `"DescribeImages"` |  |
| mainConfig.aws.threat_detection_enumeration_minutes | int | `1440` |  |
| mainConfig.aws.threat_detection_enumeration_threshold | float | `0.3` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[0] | string | `"PutUseCaseForModelAccess"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[10] | string | `"ListFoundationModels"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[11] | string | `"ListProvisionedModelThroughputs"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[1] | string | `"PutFoundationModelEntitlement"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[2] | string | `"PutModelInvocationLoggingConfiguration"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[3] | string | `"CreateFoundationModelAgreement"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[4] | string | `"InvokeModel"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[5] | string | `"InvokeModelWithResponseStream"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[6] | string | `"GetUseCaseForModelAccess"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[7] | string | `"GetModelInvocationLoggingConfiguration"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[8] | string | `"GetFoundationModelAvailability"` |  |
| mainConfig.aws.threat_detection_llm_jacking_actions[9] | string | `"ListFoundationModelAgreementOffers"` |  |
| mainConfig.aws.threat_detection_llm_jacking_minutes | int | `1440` |  |
| mainConfig.aws.threat_detection_llm_jacking_threshold | float | `0.4` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[0] | string | `"AddPermission"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[10] | string | `"CreateAccessKey"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[11] | string | `"CreateDevEndpoint"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[12] | string | `"CreateEventSourceMapping"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[13] | string | `"CreateFunction"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[14] | string | `"CreateGroup"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[15] | string | `"CreateJob"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[16] | string | `"CreateKeyPair"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[17] | string | `"CreateLoginProfile"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[18] | string | `"CreatePipeline"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[19] | string | `"CreatePolicyVersion"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[1] | string | `"AddRoleToInstanceProfile"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[20] | string | `"CreateRole"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[21] | string | `"CreateStack"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[22] | string | `"DeleteRolePermissionsBoundary"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[23] | string | `"DeleteRolePolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[24] | string | `"DeleteUserPermissionsBoundary"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[25] | string | `"DeleteUserPolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[26] | string | `"DetachRolePolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[27] | string | `"DetachUserPolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[28] | string | `"GetCredentialsForIdentity"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[29] | string | `"GetId"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[2] | string | `"AddUserToGroup"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[30] | string | `"GetPolicyVersion"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[31] | string | `"GetUserPolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[32] | string | `"Invoke"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[33] | string | `"ModifyInstanceAttribute"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[34] | string | `"PassRole"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[35] | string | `"PutGroupPolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[36] | string | `"PutPipelineDefinition"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[37] | string | `"PutRolePermissionsBoundary"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[38] | string | `"PutRolePolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[39] | string | `"PutUserPermissionsBoundary"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[3] | string | `"AssociateAccessPolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[40] | string | `"PutUserPolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[41] | string | `"ReplaceIamInstanceProfileAssociation"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[42] | string | `"RunInstances"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[43] | string | `"SetDefaultPolicyVersion"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[44] | string | `"UpdateAccessKey"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[45] | string | `"UpdateAssumeRolePolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[46] | string | `"UpdateDevEndpoint"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[47] | string | `"UpdateEventSourceMapping"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[48] | string | `"UpdateFunctionCode"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[49] | string | `"UpdateJob"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[4] | string | `"AssumeRole"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[50] | string | `"UpdateLoginProfile"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[5] | string | `"AttachGroupPolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[6] | string | `"AttachRolePolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[7] | string | `"AttachUserPolicy"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[8] | string | `"ChangePassword"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_actions[9] | string | `"CreateAccessEntry"` |  |
| mainConfig.aws.threat_detection_privilege_escalation_minutes | int | `1440` |  |
| mainConfig.aws.threat_detection_privilege_escalation_threshold | float | `0.2` |  |
| mainConfig.aws.trusted_account_ids | list | `[]` |  |
| mainConfig.aws.verify_premium_support_plans | bool | `true` |  |
| mainConfig.azure.java_latest_version | string | `"17"` |  |
| mainConfig.azure.php_latest_version | string | `"8.2"` |  |
| mainConfig.azure.python_latest_version | string | `"3.12"` |  |
| mainConfig.azure.recommended_minimal_tls_versions[0] | string | `"1.2"` |  |
| mainConfig.azure.recommended_minimal_tls_versions[1] | string | `"1.3"` |  |
| mainConfig.azure.shodan_api_key | string | `nil` |  |
| mainConfig.gcp.shodan_api_key | string | `nil` |  |
| mainConfig.kubernetes.apiserver_strong_ciphers[0] | string | `"TLS_AES_128_GCM_SHA256"` |  |
| mainConfig.kubernetes.apiserver_strong_ciphers[1] | string | `"TLS_AES_256_GCM_SHA384"` |  |
| mainConfig.kubernetes.apiserver_strong_ciphers[2] | string | `"TLS_CHACHA20_POLY1305_SHA256"` |  |
| mainConfig.kubernetes.audit_log_maxage | int | `30` |  |
| mainConfig.kubernetes.audit_log_maxbackup | int | `10` |  |
| mainConfig.kubernetes.audit_log_maxsize | int | `100` |  |
| mainConfig.kubernetes.kubelet_strong_ciphers[0] | string | `"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"` |  |
| mainConfig.kubernetes.kubelet_strong_ciphers[1] | string | `"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"` |  |
| mainConfig.kubernetes.kubelet_strong_ciphers[2] | string | `"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"` |  |
| mainConfig.kubernetes.kubelet_strong_ciphers[3] | string | `"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"` |  |
| mainConfig.kubernetes.kubelet_strong_ciphers[4] | string | `"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"` |  |
| mainConfig.kubernetes.kubelet_strong_ciphers[5] | string | `"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"` |  |
| mainConfig.kubernetes.kubelet_strong_ciphers[6] | string | `"TLS_RSA_WITH_AES_256_GCM_SHA384"` |  |
| mainConfig.kubernetes.kubelet_strong_ciphers[7] | string | `"TLS_RSA_WITH_AES_128_GCM_SHA256"` |  |
| nameOverride | string | `""` |  |
| podAnnotations | object | `{}` |  |
| podSecurityContext | object | `{}` |  |
| releaseConfigPath | string | `"prowler/config/config.yaml"` |  |
| releaseConfigRoot | string | `"/home/prowler/.cache/pypoetry/virtualenvs/prowler-api-NnJNioq7-py3.12/lib/python3.12/site-packages/"` |  |
| securityContext | object | `{}` |  |
