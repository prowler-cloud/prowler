<p align="center">
  <img align="center" src="https://github.com/prowler-cloud/prowler/blob/master/docs/img/prowler-logo-black.png#gh-light-mode-only" width="50%" height="50%">
  <img align="center" src="https://github.com/prowler-cloud/prowler/blob/master/docs/img/prowler-logo-white.png#gh-dark-mode-only" width="50%" height="50%">
</p>
<p align="center">
  <b><i>Prowler SaaS </b> and <b>Prowler Open Source</b> are as dynamic and adaptable as the environment they’re meant to protect. Trusted by the leaders in security.
</p>
<p align="center">
<b>Learn more at <a href="https://prowler.com">prowler.com</i></b>
</p>

<p align="center">
<a href="https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog"><img width="30" height="30" alt="Prowler community on Slack" src="https://github.com/prowler-cloud/prowler/assets/38561120/3c8b4ec5-6849-41a5-b5e1-52bbb94af73a"></a>
  <br>
<a href="https://join.slack.com/t/prowler-workspace/shared_invite/zt-1hix76xsl-2uq222JIXrC7Q8It~9ZNog">Join our Prowler community!</a>
</p>

# Description

**Prowler** is an Open Source security tool to perform AWS, Azure, Google Cloud and Kubernetes security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness, and also remediations! We have Prowler CLI (Command Line Interface) that we call Prowler Open Source and a service on top of it that we call <a href="https://prowler.com">Prowler SaaS</a>.

This repository contains the REST API and Task Runner components for Prowler, which facilitate a complete backend that interacts with the Prowler SDK and is used by the Prowler UI.

# Production deployment

## Install all dependencies with Poetry

```console
poetry install
poetry shell
```

## Run the Django server with Gunicorn

```console
cd src/backend
gunicorn -c backend/guniconf.py backend.wsgi:application
```

> By default, the Gunicorn server will try to use as many workers as your machine can handle. You can manually change that in the `src/backend/backend/guniconf.py` file.


# 💻 Development guide

## Local deployment

This method requires installing a Python virtual environment and keep dependencies updated.

### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/api.git

# SSH
git clone git@github.com:prowler-cloud/api.git

```

### Install the Python dependencies

> You must have Poetry installed

```console
poetry install
poetry shell
```

### Run the Django development server

```console
cd backend
python manage.py runserver
```

You can access the server in `http://localhost:8000`.
All changes in the code will be automatically reloaded in the server.


## Docker deployment

This method requires `docker` and `docker compose`.

### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/api.git

# SSH
git clone git@github.com:prowler-cloud/api.git

```

### Build the base image

```console
docker compose --profile dev build
```

### Run the development service

```console
docker compose --profile dev up
```

You can access the server in `http://localhost:8080`.
All changes in the code will be automatically reloaded in the server.

> **NOTE:** notice how the port is different. When developing using docker, the port will be `8080` to prevent conflicts.

## Modify environment variables

Under the root path of the project, you can find a file called `.env.example`. This file shows all the environment variables that the project uses. You can create a new file called `.env` and set the values for the variables.

All these variables will have a default value for the devel environment, but credentials or database connectors will be required for the production one.

Keep in mind if you export the `.env` file to use it with local deployment that you will have to do it within the context of the Poetry interpreter, not before. Otherwise, variables will not be loaded properly.



## Apply migrations

For migrations, you need to force the `admin` database router. Assuming you have the correct environment variables and Python virtual environment, run:

```console
python manage.py migrate --database admin
```

## Apply fixtures

As for migrations, with the same requirements, run:

```console
# For dev tenants
python manage.py loaddata api/fixtures/dev_tenants.json --database admin
```
