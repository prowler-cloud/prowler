#!/bin/bash

mkdir ~/.aws
cat << AWS_CREDS > ~/.aws/credentials
[${ACCOUNT_ID}]
credential_source = EcsContainer
role_arn = ${ROLE_ARN}
external_id = ${EXTERNAL_ID}

AWS_CREDS

run_prowler(){
  echo "Running prowler on customer ${CUSTOMER_NAME} with account ${ACCOUNT_ID} with check $1"
  ./prowler -p "${ACCOUNT_ID}" -c $1 -M json | tee output_$1.json
  echo "Uploading result to s3://${BUCKET}/prowler/${CUSTOMER_NAME}/${ACCOUNT_ID}/${CATEGORY}/$1/output.json"
  aws s3api put-object --bucket "${BUCKET}" --key prowler/"${CUSTOMER_NAME}"/"${ACCOUNT_ID}"/"${CATEGORY}"/$1/output.json --body output_$1.json
}
if [ "${CATEGORY}" == "IAM" ]; then
  ./prowler -p "${ACCOUNT_ID}" -c "${CHECKS}" -M json | tee output_IAM.json
  echo "Uploading result to s3://${BUCKET}/prowler/${CUSTOMER_NAME}/${ACCOUNT_ID}/${CATEGORY}/output.json"
  aws s3api put-object --bucket "${BUCKET}" --key prowler/"${CUSTOMER_NAME}"/"${ACCOUNT_ID}"/"${CATEGORY}"/output.json --body output_IAM.json
else
  IFS=', ' read -r -a checksArray <<< "$CHECKS"
  for check in "${checksArray[@]}"
  do
    run_prowler $check &
  done

  wait
fi


echo "Category: ${CATEGORY} finished"