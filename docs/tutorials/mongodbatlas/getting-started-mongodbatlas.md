# Getting Started with MongoDB Atlas

MongoDB Atlas provider enables security assessments of MongoDB Atlas cloud database deployments.

## Features

- **Authentication**: Supports MongoDB Atlas API key authentication
- **Services**: Projects and clusters services
- **Checks**: Network access security and encryption at rest validation

## Basic Usage

### Scan All Projects and Clusters

```bash
prowler mongodbatlas --atlas-public-key <key> --atlas-private-key <secret>
```
