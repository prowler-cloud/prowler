#!/usr/bin/env bash

# Prowler - the handy cloud security tool (copyright 2019) by Toni de la Fuente
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

# Remediation:
#
#   here URL to the relevand/official documentation
#
#   here commands or steps to fix it if avalable, like:
#   aws logs put-metric-filter \
#     --region us-east-1 \
#     --log-group-name CloudTrail/MyCloudTrailLG \
#     --filter-name AWSCloudTrailChanges \
#     --filter-pattern '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }' \
#     --metric-transformations metricName=CloudTrailEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

# CHECK_ID_checkN="N.N"
# CHECK_TITLE_checkN="[checkN] Description "
# CHECK_SCORED_checkN="NOT_SCORED"
# CHECK_CIS_LEVEL_checkN="EXTRA"
# CHECK_SEVERITY_checkNN="Medium"
# CHECK_ASFF_RESOURCE_TYPE_checkN="AwsAccount" # Choose appropriate value from https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html#asff-resources
# CHECK_ALTERNATE_checkN="extraN"
# CHECK_SERVICENAME_checkN="service" # get service short name from `curl -s https://api.regional-table.region-services.aws.a2z.com/index.json | jq -r '.prices[] | .id' | awk -F: '{ print $1 }' | sort -u`
# CHECK_RISK_checkN=""
# CHECK_REMEDIATION_checkN=""
# CHECK_DOC_checkN=""
# CHECK_CAF_EPIC_checkN=""

# General comments
# ----------------
# Do not add double quotes (") arround variable ${PROFILE_OPT} because this variable holds "--profile <profile-name>" and we need to read it as it is
# Always check for AccessDenied|UnauthorizedOperation|AuthorizationError after AWS CLI command, using "2>&1" at the end
# Avoid execute the same AWS CLI command again to check different attribute:
#  - Return all attributes on "--query"
#  - Use "read -r" to get all individual attributes
#  - Use "here-string" (<<<) when is necessary to interate through AWS CLI output with multiple attributes on the same line
#    - Here-string variable must be enclosed with double quotes, like "${LIST_OF_PUBLIC_INSTANCES}"
#  - See "Example of regional resource" below about how to do it
# When an attribute doesn't exist, AWS CLI "--query" always return "none" if output is json or "None" if output is text
# Use bash features to handle variable:
#  - ${var:N}      : Return string from position 'N'
#  - ${var:N:len}  : Return 'len' characters from position 'N'
#  - ${var^^}      : Convert to upper-case all characters
#  - ${var,,}      : Convert to lower-case all characters
#  - ATTENTION: macOS original bash version "GNU bash, version 3.2.57(1)-release (x86_64-apple-darwin19)" doesn't support some variable expansion above.
#               Please make sure to test it.
#  - For more examples and how to use it please refer to https://www.gnu.org/software/bash/manual/bash.html#Shell-Parameter-Expansion
# Check code with ShellCheck for best practices:
#  - https://www.shellcheck.net/
#  - https://github.com/koalaman/shellcheck#user-content-in-your-editor

# Example of regional resource
# extraN(){
#   # "Description "
#   textInfo "Looking for instances in all regions...  "
#   for regx in ${REGIONS}; do
#     LIST_OF_PUBLIC_INSTANCES=$("${AWSCLI}" ec2 describe-instances ${PROFILE_OPT} --region "${regx}" --query 'Reservations[*].Instances[?PublicIpAddress].[InstanceId,PublicIpAddress]' --output text 2>&1)
#     if [[ $(echo "${LIST_OF_PUBLIC_INSTANCES}" | grep -E 'AccessDenied|UnauthorizedOperation|AuthorizationError') ]]; then
#       textInfo "${regx}: Access Denied trying to list EC2 Instances" "${regx}"
#       continue
#     fi
#     if [[ "${LIST_OF_PUBLIC_INSTANCES}" != "" && "${LIST_OF_PUBLIC_INSTANCES,,}" != "none" ]]; then
#       while read -r INSTANCE_ID PUBLIC_IP; do
#         textFail "${regx}: Instance: ${INSTANCE_ID} at IP: ${PUBLIC_IP} is internet-facing!" "${regx}" "${INSTANCE_ID}"
#       done <<< "${LIST_OF_PUBLIC_INSTANCES}"
#     else
#       textPass "${regx}: no Internet Facing EC2 Instances found" "${regx}"
#     fi
#   done
# }

# Example of global resource
# extraN(){
#   # "Description "
#   LIST_DISTRIBUTIONS=$("${AWSCLI}" cloudfront list-distributions ${PROFILE_OPT} --query 'DistributionList.Items[*].Id' --output text 2>&1)
#   if [[ $(echo "${LIST_DISTRIBUTIONS}" | grep -E 'AccessDenied|UnauthorizedOperation|AuthorizationError') ]]; then
#     textInfo "${REGION}: Access Denied trying to list distributions" "${REGION}"
#     return
#   fi
#   if [[ "${LIST_DISTRIBUTIONS}" != "" && "${LIST_DISTRIBUTIONS,,}" != "none" ]]; then
#     for dist in ${LIST_DISTRIBUTIONS}; do
#       GEO_ENABLED=$("${AWSCLI}" cloudfront get-distribution-config $PROFILE_OPT --id "${dist}" --query 'DistributionConfig.Restrictions.GeoRestriction.RestrictionType' --output text 2>&1)
#       if [[ $(echo "${GEO_ENABLED}" | grep -E 'AccessDenied|UnauthorizedOperation|AuthorizationError') ]]; then
#         textInfo "${REGION}: Access Denied trying to get distribution config for ${dist}" "${REGION}"
#         continue
#       fi
#       if [[ "${GEO_ENABLED,,}" == "none" ]]; then
#         textFail "${REGION}: CloudFront distribution ${dist} has not Geo restrictions" "${REGION}" "${dist}"
#       else
#         textPass "${REGION}: CloudFront distribution ${dist} has Geo restrictions enabled" "${REGION}" "${dist}"
#       fi
#     done
#   else
#     textInfo "${REGION}: No CloudFront distributions found"
#   fi
# }
