#!/bin/bash

# Upgrade AWS CLI to v2
sudo yum update -y
sudo yum remove -y awscli
cd /opt || exit
sudo curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo  unzip awscliv2.zip
sudo ./aws/install
# shellcheck disable=SC1090
. ~/.profile # to load the new path for AWS CLI v2
sudo rm -fr /opt/aws/
cd ~/environment/ || exit
# Prepare Prowler 3.0
git clone https://github.com/prowler-cloud/prowler
cd prowler || exit
git checkout prowler-3.0-dev
sudo pip3 install pipenv detect-secrets==1.0.3
pipenv install && pipenv shell
