#!/bin/bash
#AMZN-Linux Terraform Install Script
git clone https://github.com/singergs/prowler.git
git fetch
cd prowler
git checkout -t origin/terraform-kickstart
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum -y install terraform
