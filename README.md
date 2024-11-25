# Description

This repository contains the JSON API and Task Runner components for Prowler, which facilitate a complete backend that interacts with the Prowler SDK and is used by the Prowler UI.

# Components
The Prowler API is composed of the following components:

- The JSON API, which is an API built with Django Rest Framework.
- The Celery worker, which is responsible for executing the background tasks that are defined in the JSON API.
- The PostgreSQL database, which is used to store the data.
- The Valkey database, which is an in-memory database which is used as a message broker for the Celery workers.

## Note about Valkey

[Valkey](https://valkey.io/) is an open source (BSD) high performance key/value datastore.

Valkey exposes a Redis 7.2 compliant API. Any service that exposes the Redis API can be used with Prowler API.

# Modify environment variables

Under the root path of the project, you can find a file called `.env.example`. This file shows all the environment variables that the project uses. You *must* create a new file called `.env` and set the values for the variables.

## Local deployment
Keep in mind if you export the `.env` file to use it with local deployment that you will have to do it within the context of the Poetry interpreter, not before. Otherwise, variables will not be loaded properly.

To do this, you can run:

```console
poetry shell
set -a
source .env
```

# 🚀 Production deployment
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
docker compose --profile prod build
```

### Run the production service

This command will start the Django production server and the Celery worker and also the Valkey and PostgreSQL databases.

```console
docker compose --profile prod up -d
```

You can access the server in `http://localhost:8080`.

> **NOTE:** notice how the port is different. When developing using docker, the port will be `8080` to prevent conflicts.

### View the Production Server Logs

To view the logs for any component (e.g., Django, Celery worker), you can use the following command with a wildcard. This command will follow logs for any container that matches the specified pattern:

```console
docker logs -f $(docker ps --format "{{.Names}}" | grep 'api-')

## Local deployment

To use this method, you'll need to set up a Python virtual environment (version ">=3.11,<3.13") and keep dependencies updated. Additionally, ensure that `poetry` and `docker compose` are installed.

### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/api.git

# SSH
git clone git@github.com:prowler-cloud/api.git

```
### Install all dependencies with Poetry

```console
poetry install
poetry shell
```

## Start the PostgreSQL Database and Valkey

The PostgreSQL database (version 16.3) and Valkey (version 7) are required for the development environment. To make development easier, we have provided a `docker-compose` file that will start these components for you.

**Note:** Make sure to use the specified versions, as there are features in our setup that may not be compatible with older versions of PostgreSQL and Valkey.


```console
docker compose up postgres valkey -d
```

## Deploy Django and the Celery worker

### Run migrations

For migrations, you need to force the `admin` database router. Assuming you have the correct environment variables and Python virtual environment, run:

```console
cd src/backend
python manage.py migrate --database admin
```

### Run the Celery worker

```console
cd src/backend
python -m celery -A config.celery worker -l info -E
```

### Run the Django server with Gunicorn

```console
cd src/backend
gunicorn -c config/guniconf.py config.wsgi:application
```

> By default, the Gunicorn server will try to use as many workers as your machine can handle. You can manually change that in the `src/backend/config/guniconf.py` file.

# 🧪 Development guide

## Local deployment

To use this method, you'll need to set up a Python virtual environment (version ">=3.11,<3.13") and keep dependencies updated. Additionally, ensure that `poetry` and `docker compose` are installed.

### Clone the repository

```console
# HTTPS
git clone https://github.com/prowler-cloud/api.git

# SSH
git clone git@github.com:prowler-cloud/api.git

```

### Start the PostgreSQL Database and Valkey

The PostgreSQL database (version 16.3) and Valkey (version 7) are required for the development environment. To make development easier, we have provided a `docker-compose` file that will start these components for you.

**Note:** Make sure to use the specified versions, as there are features in our setup that may not be compatible with older versions of PostgreSQL and Valkey.


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
cd src/backend
python manage.py migrate --database admin
```

### Run the Django development server

```console
cd src/backend
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

To view the logs for any component (e.g., Django, Celery worker), you can use the following command with a wildcard. This command will follow logs for any container that matches the specified pattern:

```console
docker logs -f $(docker ps --format "{{.Names}}" | grep 'api-')

## Applying migrations

For migrations, you need to force the `admin` database router. Assuming you have the correct environment variables and Python virtual environment, run:

```console
poetry shell
cd src/backend
python manage.py migrate --database admin
```

## Apply fixtures

Fixtures are used to populate the database with initial development data.

```console
poetry shell
cd src/backend
python manage.py loaddata api/fixtures/0_dev_users.json --database admin
```

> The default credentials are `dev@prowler.com:thisisapassword123` or `dev2@prowler.com:thisisapassword123`

## Run tests

Note that the tests will fail if you use the same `.env` file as the development environment.

For best results, run in a new shell with no environment variables set.

```console
poetry shell
cd src/backend
pytest
```
