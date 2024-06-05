#!/bin/bash

# Install system dependencies
sudo yum -y install openssl-devel bzip2-devel libffi-devel gcc
# Upgrade to Python 3.9
cd /tmp && wget https://www.python.org/ftp/python/3.9.13/Python-3.9.13.tgz
tar zxf Python-3.9.13.tgz
cd Python-3.9.13/ || exit
./configure --enable-optimizations
sudo make altinstall
python3.9 --version
# Install Prowler
cd ~ || exit
python3.9 -m pip install prowler-cloud
prowler -v
# Run Prowler
prowler aws
