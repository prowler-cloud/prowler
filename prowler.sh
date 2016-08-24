#!/bin/bash

# Prowler is a tool that provides automate auditing and hardening guidance of an AWS account.
# It is based on AWS-CLI commands. It follows guidelines present in the CIS Amazon
# Web Services Foundations Benchmark at:
# https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf

# This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0
# International Public License. The link to the license terms can be found at
# https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode
#
# Author: Toni de la Fuente - @ToniBlyx / Alfresco Software Inc.

# Prowler - Iron Maiden
#
# Walking through the city, looking oh so pretty
# I've just got to find my way
# See the ladies flashing
# All there legs and lashes
# I've just got to find my way...

# Safety feature: exit script if error is returned, or if variables not set.
# Exit if a pipeline results in an error.
# set -ue
# set -o pipefail
# set -vx

# Exits if any error is found
set -e

# Colors
NORMAL="[0;39m"
WARNING="[1;33m"          # Bad (red)
SECTION="[1;33m"          # Section (yellow)
NOTICE="[1;33m"           # Notice (yellow)
OK="[1;32m"               # Ok (green)
BAD="[1;31m"              # Bad (red)
CYAN="[0;36m"
BLUE="[0;34m"
BROWN="[0;33m"
DARKGRAY="[0;30m"
GRAY="[0;37m"
GREEN="[1;32m"
MAGENTA="[1;35m"
PURPLE="[0;35m"
RED="[1;31m"
YELLOW="[1;33m"
WHITE="[1;37m"

DEFULT_AWS_PROFILE="default"
DEFAULT_AWS_REGION="us-east-1"

# Command usage menu
usage(){
  echo -e "\nUSAGE:
      `basename $0` -p <profile> -r <region> [ -v ] [ -h ]
  Options:
      -p <profile>  specify your AWS profile to use (i.e.: default)
      -r <region>   specify a desired AWS region to use (i.e.: us-east-1)
      -v            enable vervose mode
      -h            this help
  "
  exit
}

while getopts "hp:r:" OPTION; do
   case $OPTION in
     h )
        usage
        exit 1
        ;;
     p )
        PROFILE=$OPTARG
        ;;
     r )
        REGION=$OPTARG
        ;;
     : )
        echo -e "\n$RED ERROR!$NORMAL  -$OPTARG requires an argument\n"
        exit 1
        ;;
     ? )
        echo -e "\n$RED ERROR!$NORMAL Invalid option"
        usage
        exit 1
        ;;
   esac
done

if (($# == 0)); then
  PROFILE=$DEFULT_AWS_PROFILE
  REGION=$DEFAULT_AWS_REGION
fi

if [[ ! -f ~/.aws/credentials ]]; then
  echo -e "\n$RED ERROR!$NORMAL AWS credentials file not found (~/.aws/credentials). Run 'aws configure' first. \n"
  return 1
fi

# AWS-CLI variables
AWSCLI=$(which aws)
if [ -z "${AWSCLI}" ]; then
  echo -e "\n$RED ERROR!$NORMAL AWS-CLI (aws command) not found. Make sure it is installed correctly and in your \$PATH\n"
  exit
fi

# if [ -z "${PROFILE}" ] || [ -z "${REGION}" ]; then
#   PROFILE=$($AWSCLI configure list | grep "profile" | awk '{ print $2 }')
#   REGION=$($AWSCLI configure list | grep "region" | awk '{ print $2 }')
#   if [ -z "${PROFILE}" ] || [ -z "${REGION}" ]; then
#     echo -e "\n $RED ERROR!$NORMAL No profile or region found, configure it using 'aws configure'\n"
#     echo -e "     or specify options -p <profile> -r <region>\n"
#     exit
#   fi
# fi

# if this script runs in an AWS instance
# INSTANCE_PROFILE=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)
# AWS_ACCESS_KEY_ID=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/${INSTANCE_PROFILE} | grep AccessKeyId | cut -d':' -f2 | sed 's/[^0-9A-Z]*//g')
# AWS_SECRET_ACCESS_KEY_ID=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/${INSTANCE_PROFILE} | grep SecretAccessKey | cut -d':' -f2 | sed 's/[^0-9A-Za-z/+=]*//g')
# AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
# AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY_ID}

#cat ~/.aws/credentials

TITLE1="$BLUE 1 Identity and Access Management$NORMAL"
TITLE11="$BLUE 1.1$NORMAL Avoid the use of the root account (Scored). Last time root account was used
   (password last used, access_key_1_last_used, access_key_2_last_used): "
TITLE12="$BLUE 1.2$NORMAL Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)"
TITLE13="$BLUE 1.3$NORMAL Ensure credentials unused for 90 days or greater are disabled (Scored)"
TITLE14="$BLUE 1.4$NORMAL Ensure access keys are rotated every 90 days or less (Scored)"
TITLE15="$BLUE 1.5$NORMAL Ensure IAM password policy requires at least one uppercase letter (Scored)"
TITLE16="$BLUE 1.6$NORMAL Ensure IAM password policy require at least one lowercase letter (Scored)"
TITLE17="$BLUE 1.7$NORMAL Ensure IAM password policy require at least one symbol (Scored)"
TITLE18="$BLUE 1.8$NORMAL Ensure IAM password policy require at least one number (Scored)"
TITLE19="$BLUE 1.9$NORMAL Ensure IAM password policy requires minimum length of 14 or greater (Scored)"
TITLE110="$BLUE 1.10$NORMAL Ensure IAM password policy prevents password reuse (Scored)"
TITLE111="$BLUE 1.11$NORMAL Ensure IAM password policy expires passwords within 90 days or less (Scored)"
TITLE112="$BLUE 1.12$NORMAL Ensure no root account access key exists (Scored)"
TITLE113="$BLUE 1.13$NORMAL Ensure hardware MFA is enabled for the root account (Scored)"
TITLE114="$BLUE 1.14$NORMAL Ensure security questions are registered in the AWS account (Not Scored)"
TITLE115="$BLUE 1.15$NORMAL Ensure IAM policies are attached only to groups or roles (Scored)"
TITLE2="$BLUE 2 Logging$NORMAL"
TITLE21="$BLUE 2.1$NORMAL Ensure CloudTrail is enabled in all regions (Scored)"
TITLE22="$BLUE 2.2$NORMAL Ensure CloudTrail log file validation is enabled (Scored)"
TITLE23="$BLUE 2.3$NORMAL Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)"
TITLE24="$BLUE 2.4$NORMAL Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)"
TITLE25="$BLUE 2.5$NORMAL Ensure AWS Config is enabled in all regions (Scored)"
TITLE26="$BLUE 2.6$NORMAL Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)"
TITLE27="$BLUE 2.7$NORMAL Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)"
TITLE28="$BLUE 2.8$NORMAL Ensure rotation for customer created CMKs is enabled (Scored)"
TITLE3="$BLUE 3 Monitoring"
TITLE31="$BLUE 3.1$NORMAL Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)"
TITLE32="$BLUE 3.2$NORMAL Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)"
TITLE33="$BLUE 3.3$NORMAL Ensure a log metric filter and alarm exist for usage of root account (Scored)"
TITLE34="$BLUE 3.4$NORMAL Ensure a log metric filter and alarm exist for IAM policy changes (Scored)"
TITLE35="$BLUE 3.5$NORMAL Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)"
TITLE36="$BLUE 3.6$NORMAL Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)"
TITLE37="$BLUE 3.7$NORMAL Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)"
TITLE38="$BLUE 3.8$NORMAL Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)"
TITLE39="$BLUE 3.9$NORMAL Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)"
TITLE310="$BLUE 3.10$NORMAL Ensure a log metric filter and alarm exist for security group changes (Scored)"
TITLE311="$BLUE 3.11$NORMAL Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)"
TITLE312="$BLUE 3.12$NORMAL Ensure a log metric filter and alarm exist for changes to network gateways (Scored)"
TITLE313="$BLUE 3.13$NORMAL Ensure a log metric filter and alarm exist for route table changes (Scored)"
TITLE314="$BLUE 3.14$NORMAL Ensure a log metric filter and alarm exist for VPC changes (Scored)"
TITLE315="$BLUE 3.15$NORMAL Ensure security contact information is registered (Scored)"
TITLE316="$BLUE 3.16$NORMAL Ensure appropriate subscribers to each SNS topic (Not Scored)"
TITLE4="$BLUE 4 Networking$NORMAL"
TITLE41="$BLUE 4.1$NORMAL Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)"
TITLE42="$BLUE 4.2$NORMAL Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)"
TITLE43="$BLUE 4.3$NORMAL Ensure VPC Flow Logging is Enabled in all Applicable Regions (Scored)"
TITLE44="$BLUE 4.4$NORMAL Ensure the default security group restricts all traffic (Scored)"

# Get whoami in AWS, who is the user running this shell script
getWhoami() {
  echo -e '\n This report is being generated using credentials below:\n'
  echo -e "\n AWS-CLI Profile: $NOTICE[$PROFILE]$NORMAL AWS Region: $NOTICE[$REGION]$NORMAL\n"
  $AWSCLI sts get-caller-identity --output table --profile $PROFILE --region $REGION
}
getWhoami

echo -e "\nColors Code for results: $NOTICE INFORMATIVE$NORMAL,$OK CORRECT (RECOMMENDED VALUE)$NORMAL, $BAD CRITICAL (FIX REQUIRED)$NORMAL  \n"

# Generate Credential Report
genCredReport() {
  echo -en '\nGenerating Credential Report...'
  while STATE=$($AWSCLI iam generate-credential-report --output text --query 'State' --profile $PROFILE --region $REGION)
    test "$STATE" = "STARTED"
    #test "$STATE" = "COMPLETE"
  do
    sleep 1
    echo -n '.'
  done
  echo -en " $STATE!"
}
genCredReport

REGIONS=$($AWSCLI ec2 describe-regions --query 'Regions[].RegionName' \
  --output text \
  --profile $PROFILE \
  --region $REGION)


# 1 Identity and Access Management check commands
COMMAND11=$($AWSCLI iam get-credential-report --query 'Content' --output text --profile $PROFILE --region $REGION| base64 -D | grep '<root_account>' | cut -d, -f5,11,16)
# COMMAND12=$($AWSCLI iam generate-credential-report --profile $PROFILE --region $REGION; $AWSCLI iam get-credential-report --query 'Content' --output text --profile $PROFILE --region $REGION| base64 -D | cut -d, -f1,4,8)
# COMMAND13=$($AWSCLI iam generate-credential-report --profile $PROFILE --region $REGION; $AWSCLI iam get-credential-report --query 'Content' --output text --profile $PROFILE --region $REGION| base64 -D) # checked by Security Monkey
# COMMAND14=$($AWSCLI iam generate-credential-report --profile $PROFILE --region $REGION; $AWSCLI iam get-credential-report --query 'Content' --output text --profile $PROFILE --region $REGION| base64 -D) # checked by Security Monkey
# COMMAND15=$($AWSCLI iam get-account-password-policy --profile $PROFILE --region $REGION| grep RequireUppercaseCharacters) # must be true
# COMMAND16=$($AWSCLI iam get-account-password-policy --profile $PROFILE --region $REGION| grep RequireLowercaseCharacters) # must be true
# COMMAND17=$($AWSCLI iam get-account-password-policy --profile $PROFILE --region $REGION| grep RequireSymbols) # must be true
# COMMAND18=$($AWSCLI iam get-account-password-policy --profile $PROFILE --region $REGION| grep RequireNumbers) # must be true
# COMMAND19=$($AWSCLI iam get-account-password-policy --profile $PROFILE --region $REGION| grep MinimumPasswordLength) # must be 14
# COMMAND110=$($AWSCLI iam get-account-password-policy --profile $PROFILE --region $REGION| grep PasswordReusePrevention) # must be 24
# COMMAND111=$($AWSCLI iam get-account-password-policy --profile $PROFILE --region $REGION| grep MaxPasswordAge) # must be 90
# COMMAND112=$($AWSCLI iam generate-credential-report --profile $PROFILE --region $REGION; $AWSCLI iam get-credential-report --query 'Content' --output text --profile $PROFILE --region $REGION| base64 -D) # ensure the access_key_1_active and access_key_2_active fields are set to FALSE.
# COMMAND113=$($AWSCLI iam get-account-summary --profile $PROFILE --region $REGION| grep AccountMFAEnabled) # must be 1
# Review 14, no command available
# COMMAND114=$(for i in $($AWSCLI iam list-users --query 'Users[*].UserName' --output text --profile $PROFILE --region $REGION); do echo $i;$AWSCLI iam list-attached-user-policies --user-name $i --profile $PROFILE --region $REGION; $AWSCLI iam list-user-policies --user-name $i --profile $PROFILE --region $REGION; done)
# COMMAND115=$($AWSCLI iam generate-credential-report --profile $PROFILE --region $REGION; $AWSCLI iam get-credential-report --query 'Content' --output text --profile $PROFILE --region $REGION| base64 -D | grep root_account | awk -F, '{ print $1"\t" $9"\t" $14 }') # both must be false

echo -e "\n $TITLE1"
echo -e "\n $TITLE11 $NOTICE $COMMAND11 $NORMAL"

# 2 Logging check commands
# COMMAND21=$($AWSCLI  cloudtrail describe-trails --profile $PROFILE --region $REGION| grep IsMultiRegionTrail) # must be true
# COMMAND22=$($AWSCLI  cloudtrail describe-trails --profile $PROFILE --region $REGION| grep LogFileValidationEnabled) # must be true
# COMMAND23=$($AWSCLI  s3api get-bucket-acl --bucket $(aws cloudtrail describe-trails --query 'trailList[*].S3BucketName' --profile $PROFILE --region $REGION --output text --profile $PROFILE --region $REGION) --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' --profile $PROFILE --region $REGION # must be empty
# $AWSCLI  s3api get-bucket-acl --bucket $(aws cloudtrail describe-trails --query 'trailList[*].S3BucketName' --profile $PROFILE --region $REGION --output text) --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/Authenticated Users`]' --profile $PROFILE --region $REGION # must be empty
# $AWSCLI  s3api get-bucket-policy --bucket usm-cloudtrail--1066738384 --profile $PROFILE --region $REGION) # must be empty or not policy"
# COMMAND24=$(for i in $($AWSCLI  cloudtrail describe-trails --profile $PROFILE --region $REGION --query 'trailList[*].Name' --output text); do aws cloudtrail get-trail-status --name $i --profile $PROFILE --region $REGION | grep LatestcloudwatchLogdDeliveryTime; done) # it must be set to ~one day old
# COMMAND25=$(aws configservice get-status --profile $PROFILE --region $REGION) # must be set
# COMMAND26=$(for i in $($AWSCLI  cloudtrail describe-trails --query 'trailList[*].S3BucketName' --profile $PROFILE --region $REGION --output text); do aws s3api get-bucket-logging --bucket $i --profile $PROFILE --region $REGION; done) # must be enabled
# COMMAND27=$(for i in $($AWSCLI  cloudtrail describe-trails --profile $PROFILE --region $REGION --query 'trailList[*].Name' --output text); do aws cloudtrail describe-trails --profile $PROFILE --region $REGION; done |grep KmsKeyId) # it can NOT be empty
# COMMAND28=$(for i in $($AWSCLI  kms list-keys --query 'Keys[*].KeyId' --output text --profile $PROFILE --region $REGION); do echo $i; aws kms get-key-rotation-status --key-id $i --profile $PROFILE --region $REGION; done) # must be true

# 3 Monitoring check commands / Mostly covered by SecurityMonkey
#COMMAND31=$AWSCLI  cloudtrail describe-trails --profile $PROFILE --region $REGION | take group ARN | aws logs describe-metric-filters --log-group-name "<group>"
COMMAND32=
COMMAND33=
COMMAND34=
COMMAND35=
COMMAND36=
COMMAND37=
COMMAND38=
COMMAND39=
COMMAND310=
COMMAND311=
COMMAND312=
COMMAND313=
COMMAND314=
COMMAND315=
COMMAND316=

# 4 Networking check commands
# COMMAND41= THIS MAY HELP: aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" --query "SecurityGroups[].[GroupId, GroupName]" --profile $PROFILE --region $REGION
# COMMAND42= same above for here
# COMMAND43= Ensure VPC Flow Logging is Enabled in all Applicable Regions
#COMMAND44= Ensure the default security group restricts all traffic

# Report result
echo -e "\n$TITLE1\n "
echo -e "$TITLE11 "
echo -e "$TITLE12 "
echo -e "$TITLE13 "
echo -e "$TITLE14 "
echo -e "$TITLE15 "
echo -e "$TITLE16 "
echo -e "$TITLE17 "
echo -e "$TITLE18 "
echo -e "$TITLE19 "
echo -e "$TITLE110 "
echo -e "$TITLE111 "
echo -e "$TITLE112 "
echo -e "$TITLE113 "
echo -e "$TITLE114 "
echo -e "$TITLE115 "
echo -e "\n$TITLE2\n "
echo -e "$TITLE21 "
echo -e "$TITLE22 "
echo -e "$TITLE23 "
echo -e "$TITLE24 "
echo -e "$TITLE25 "
echo -e "$TITLE26 "
echo -e "$TITLE27 "
echo -e "$TITLE28 "
echo -e "\n$TITLE3\n "
echo -e "$TITLE31 "
echo -e "$TITLE32 "
echo -e "$TITLE33 "
echo -e "$TITLE34 "
echo -e "$TITLE35 "
echo -e "$TITLE36 "
echo -e "$TITLE37 "
echo -e "$TITLE38 "
echo -e "$TITLE39 "
echo -e "$TITLE310 "
echo -e "$TITLE311 "
echo -e "$TITLE312 "
echo -e "$TITLE313 "
echo -e "$TITLE314 "
echo -e "$TITLE315 "
echo -e "$TITLE316 "
echo -e "\n$TITLE4\n "
echo -e "$TITLE41 "
echo -e "$TITLE42 "
echo -e "$TITLE43 "
echo -e "$TITLE44 "


# Final
echo -e "\nFor more information and reference: https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf"
