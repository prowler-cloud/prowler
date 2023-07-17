# AWS CloudShell

Prowler can be easily executed in AWS CloudShell but it has some prerequisites to be able to to so. AWS CloudShell is a container running with `Amazon Linux release 2 (Karoo)` that comes with Python 3.7, since Prowler requires Python >= 3.9 we need to first install a newer version of Python. Follow the steps below to successfully execute Prowler v3 in AWS CloudShell:

- First install all dependences and then Python, in this case we need to compile it because there is not a package available at the time this document is written:
```
sudo yum -y install gcc openssl-devel bzip2-devel libffi-devel
wget https://www.python.org/ftp/python/3.9.16/Python-3.9.16.tgz
tar zxf Python-3.9.16.tgz
cd Python-3.9.16/
./configure --enable-optimizations
sudo make altinstall
python3.9 --version
cd 
```
- Once Python 3.9 is available we can install Prowler from pip:
```
pip3.9 install prowler
```
- Now enjoy Prowler:
```
prowler -v
prowler 
```

- To download the results from AWS CloudShell, select Actions -> Download File and add the full path of each file. For the CSV file it will be something like `/home/cloudshell-user/output/prowler-output-123456789012-20221220191331.csv`