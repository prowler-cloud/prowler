#!/bin/bash
AccountId=$1
Alias=$2

echo $AWS_ACCESS_KEY_ID
python3 credentials.py $AccountId

echo $AWS_ACCESS_KEY_ID
echo $AWS_ACCESS_KEY_ID2
echo "Running prowler on $Alias"
./prowler -c extra741 -M json > output.json

unset AWS_ACCESS_KEY_ID
echo $AWS_ACCESS_KEY_ID
