
Prowler App is a web application that simplifies running Prowler. It provides:

- A **user-friendly interface** for configuring and executing scans.
- A dashboard to **view results** and manage **security findings**.

![Prowler App](img/overview.png)

## Components

The **Prowler App** consists of three main components:

- **Prowler UI**: A user-friendly web interface for running Prowler and viewing results, powered by Next.js.
- **Prowler API**: The backend API that executes Prowler scans and stores the results, built with Django REST Framework.
- **Prowler SDK**: A Python SDK that integrates with Prowler CLI for advanced functionality.

The app leverages the following supporting infrastructure:

- **PostgreSQL**: Used for persistent storage of scan results.
- **Celery Workers**: Facilitate asynchronous execution of Prowler scans.
- **Valkey**: An in-memory database serving as a message broker for the Celery workers.

![Prowler App Architecture](img/prowler-app-architecture.png)
