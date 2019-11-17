#!/bin/bash

python3 credentials.py $ACCOUNT_ID

echo "Running prowler on $ALIAS"
./prowler -c extra741 -M json > output.json

cat output.json

aws s3api put-object --bucket $BUCKET --key prowler/$ACCOUNT_ID/results