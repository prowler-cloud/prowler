#!/bin/bash

sudo bash
adduser prowler
su prowler
pip install prowler
cd /tmp
prowler aws
