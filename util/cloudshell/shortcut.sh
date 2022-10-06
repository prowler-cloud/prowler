#!/bin/bash

# ShortCut - Run Prowler and ScoutSuite in Customer's environment using AWS CloudShell
# DozerCat - Team DragonCat - AWS

# Package Prerequisites
sudo yum update -y
sudo yum install python3 -y
sudo yum install screen -y
sudo yum install zip -y

# Variable and Environment Prerequisites
account=$(aws sts get-caller-identity | jq --raw-output '.Account')
mkdir ${account}-results

# Prowler
cd ~
git clone https://github.com/prowler-cloud/prowler
pip3 install detect-secrets --user
cd prowler 
screen -dmS prowler sh -c "./prowler -M csv,html;cd ~;zip -r ${account}-results/prowler-${account}.zip /home/cloudshell-user/prowler/output"

# Check on screen sessions
screen -ls
