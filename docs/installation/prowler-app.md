### Installation

Prowler App supports multiple installation methods based on your environment.

Refer to the [Prowler App Tutorial](../tutorials/prowler-app.md) for detailed usage instructions.

=== "Docker Compose"

    _Requirements_:

    * `Docker Compose` installed: https://docs.docker.com/compose/install/.

    _Commands_:

    ``` bash
    curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/docker-compose.yml
    curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/.env
    docker compose up -d
    ```

    > Containers are built for `linux/amd64`. If your workstation's architecture is different, please set `DOCKER_DEFAULT_PLATFORM=linux/amd64` in your environment or use the `--platform linux/amd64` flag in the docker command.

    > Enjoy Prowler App at http://localhost:3000 by signing up with your email and password.

    ???+ note
        You can change the environment variables in the `.env` file. Note that it is not recommended to use the default values in production environments.

    ???+ note
        There is a development mode available, you can use the file https://github.com/prowler-cloud/prowler/blob/master/docker-compose-dev.yml to run the app in development mode.

    ???+ warning
        Google and GitHub authentication is only available in [Prowler Cloud](https://prowler.com).

=== "GitHub"

    _Requirements_:

    * `git` installed.
    * `poetry` installed: [poetry installation](https://python-poetry.org/docs/#installation).
    * `npm` installed: [npm installation](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).
    * `Docker Compose` installed: https://docs.docker.com/compose/install/.

    ???+ warning
        Make sure to have `api/.env` and `ui/.env.local` files with the required environment variables. You can find the required environment variables in the [`api/.env.template`](https://github.com/prowler-cloud/prowler/blob/master/api/.env.example) and [`ui/.env.template`](https://github.com/prowler-cloud/prowler/blob/master/ui/.env.template) files.

    _Commands to run the API_:

    ``` bash
    git clone https://github.com/prowler-cloud/prowler \
    cd prowler/api \
    poetry install \
    eval $(poetry env activate) \
    set -a \
    source .env \
    docker compose up postgres valkey -d \
    cd src/backend \
    python manage.py migrate --database admin \
    gunicorn -c config/guniconf.py config.wsgi:application
    ```

    ???+ important
        Starting from Poetry v2.0.0, `poetry shell` has been deprecated in favor of `poetry env activate`.

        If your poetry version is below 2.0.0 you must keep using `poetry shell` to activate your environment.
        In case you have any doubts, consult the Poetry environment activation guide: https://python-poetry.org/docs/managing-environments/#activating-the-environment

    > Now, you can access the API documentation at http://localhost:8080/api/v1/docs.

    _Commands to run the API Worker_:

    ``` bash
    git clone https://github.com/prowler-cloud/prowler \
    cd prowler/api \
    poetry install \
    eval $(poetry env activate) \
    set -a \
    source .env \
    cd src/backend \
    python -m celery -A config.celery worker -l info -E
    ```

    _Commands to run the API Scheduler_:

    ``` bash
    git clone https://github.com/prowler-cloud/prowler \
    cd prowler/api \
    poetry install \
    eval $(poetry env activate) \
    set -a \
    source .env \
    cd src/backend \
    python -m celery -A config.celery beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
    ```

    _Commands to run the UI_:

    ``` bash
    git clone https://github.com/prowler-cloud/prowler \
    cd prowler/ui \
    npm install \
    npm run build \
    npm start
    ```

    > Enjoy Prowler App at http://localhost:3000 by signing up with your email and password.

    ???+ warning
        Google and GitHub authentication is only available in [Prowler Cloud](https://prowler.com).


### Update

You have two options to upgrade your Prowler App installation:

#### Option 1: Change env file with the following values

Edit your `.env` file and change the version values:

```env
PROWLER_UI_VERSION="5.9.0"
PROWLER_API_VERSION="5.9.0"
```

#### Option 2: Run the following command

```bash
docker compose pull --policy always
```

The `--policy always` flag ensures that Docker pulls the latest images even if they already exist locally.


???+ note "What Gets Preserved During Upgrade"

    Everything is preserved, nothing will be deleted after the update.

### Troubleshooting

If containers don't start, check logs for errors:

```bash
# Check logs for errors
docker compose logs

# Verify image versions
docker images | grep prowler
```

If you encounter issues, you can rollback to the previous version by changing the `.env` file back to your previous version and running:

```bash
docker compose pull
docker compose up -d
```


### Container versions

The available versions of Prowler CLI are the following:

- `latest`: in sync with `master` branch (please note that it is not a stable version)
- `v4-latest`: in sync with `v4` branch (please note that it is not a stable version)
- `v3-latest`: in sync with `v3` branch (please note that it is not a stable version)
- `<x.y.z>` (release): you can find the releases [here](https://github.com/prowler-cloud/prowler/releases), those are stable releases.
- `stable`: this tag always point to the latest release.
- `v4-stable`: this tag always point to the latest release for v4.
- `v3-stable`: this tag always point to the latest release for v3.

The container images are available here:

- Prowler App:

    - [DockerHub - Prowler UI](https://hub.docker.com/r/prowlercloud/prowler-ui/tags)
    - [DockerHub - Prowler API](https://hub.docker.com/r/prowlercloud/prowler-api/tags)
