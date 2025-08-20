Prowler App is a web application that simplifies running Prowler. It provides:

- **User-friendly interface** for configuring and executing scans
- Dashboard to **view results** and manage **security findings**

![Prowler App](img/overview.png)

## Components

Prowler App consists of three main components:

- **Prowler UI**: User-friendly web interface for running Prowler and viewing results, powered by Next.js
- **Prowler API**: Backend API that executes Prowler scans and stores results, built with Django REST Framework
- **Prowler SDK**: Python SDK that integrates with Prowler CLI for advanced functionality

Supporting infrastructure includes:

- **PostgreSQL**: Persistent storage of scan results
- **Celery Workers**: Asynchronous execution of Prowler scans
- **Valkey**: In-memory database serving as message broker for Celery workers

![Prowler App Architecture](img/prowler-app-architecture.png)
