#!/bin/bash

sudo bash
env | grep AWS_CONTAINER_AUTHORIZATION_TOKEN
adduser prowler
su - prowler
export AWS_CONTAINER_AUTHORIZATION_TOKEN=GIVEN-VALUE
export AWS_CONTAINER_CREDENTIALS_FULL_URI=http://localhost:1338/latest/meta-data/container/security-credentials
pip install prowler
prowler aws
