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

This repository contains the JSON API and Task Runner components for Prowler, which facilitate a complete backend that interacts with the Prowler SDK and is used by the Prowler UI.

# Production deployment

## Install all dependencies with Poetry

```console
poetry install
poetry shell
```

## Modify environment variables

Under the root path of the project, you can find a file called `.env.example`. This file shows all the environment variables that the project uses. You can *must* create a new file called `.env` and set the values for the variables.

Keep in mind if you export the `.env` file to use it with local deployment that you will have to do it within the context of the Poetry interpreter, not before. Otherwise, variables will not be loaded properly.

## Run migrations

For migrations, you need to force the `admin` database router. Assuming you have the correct environment variables and Python virtual environment, run:

```console
python manage.py migrate --database admin
```

## Run the Celery worker

```console
cd src/backend
python -m celery -A config.celery worker -l info -E
```

## Run the Django server with Gunicorn

```console
cd src/backend
gunicorn -c backend/guniconf.py backend.wsgi:application
```

> By default, the Gunicorn server will try to use as many workers as your machine can handle. You can manually change that in the `src/backend/backend/guniconf.py` file.

# 💻 Development guide

The Prowler API is composed of the following components:

- The JSON API, which is the main component of the API.
- The Celery worker, which is responsible for executing the background tasks that are defined in the JSON API.
- The PostgreSQL database, which is used to store the data.
- The Valkey database, which is used to manage the background tasks.

## Note about Valkey

[Valkey](https://valkey.io/) is an open source (BSD) high performance key/value datastore.

Valkey exposes a Redis 7.2 compliant API. Any service that exposes the Redis API can be used with Prowler API.

## Local deployment

This method requires installing a Python virtual environment and keep dependencies updated.

### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/api.git

# SSH
git clone git@github.com:prowler-cloud/api.git

```

### Start the PostgreSQL database and Valkey

The PostgreSQL database and Valkey are required for the development environment. To make development easier, we have provided a docker-compose file that will start them for you.

```console
docker compose up postgres valkey -d
```

### Install the Python dependencies

> You must have Poetry installed

```console
poetry install
poetry shell
```

### Apply migrations

For migrations, you need to force the `admin` database router. Assuming you have the correct environment variables and Python virtual environment, run:

```console
python manage.py migrate --database admin
```

### Run the Django development server

```console
cd backend
python manage.py migrate --database admin
python manage.py runserver
```

You can access the server in `http://localhost:8000`.
All changes in the code will be automatically reloaded in the server.

### Run the Celery worker

```console
python -m celery -A config.celery worker -l info -E
```

The Celery worker does not detect and reload changes in the code, so you need to restart it manually when you make changes.

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

This command will start the Django development server and the Celery worker and also the Valkey and PostgreSQL databases.

```console
docker compose --profile dev up -d
```

You can access the server in `http://localhost:8080`.
All changes in the code will be automatically reloaded in the server.

> **NOTE:** notice how the port is different. When developing using docker, the port will be `8080` to prevent conflicts.

### View the development server logs

For Django

```console
docker logs -f api-api-dev-1
```

or for the Celery worker:

```console
docker logs -f api-worker-dev-1
```

## Applying migrations

For migrations, you need to force the `admin` database router. Assuming you have the correct environment variables and Python virtual environment, run:

```console
poetry shell
python manage.py migrate --database admin
```

## Apply fixtures

Fixtures are used to populate the database with initial development data.

```console
poetry shell
# For dev users
python manage.py loaddata api/fixtures/0_dev_users.json --database admin
```

> The default credentials are `prowler_dev:thisisapassword123`

## Run tests

Note that the tests will fail if you use the same `.env` file as the development environment.

For best results, run in a new shell with no environment variables set.

```console
poetry shell
cd src/backend
pytest
```
