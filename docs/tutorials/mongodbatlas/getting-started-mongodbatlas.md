# Getting Started with MongoDB Atlas

## Prowler CLI

### Authentication Methods

#### Command-Line Arguments


```bash
prowler mongodbatlas --atlas-public-key <public_key> --atlas-private-key <private_key>
```

#### Environment Variables

```bash
export ATLAS_PUBLIC_KEY=<public_key>
export ATLAS_PRIVATE_KEY=<private_key>
prowler mongodbatlas
```



### Scan All Projects and Clusters

After storing your API keys, you can run Prowler with the following command:

```bash
prowler mongodbatlas --atlas-public-key <key> --atlas-private-key <secret>
```

Also, you can set your API keys as environment variables:

```bash
export ATLAS_PUBLIC_KEY=<key>
export ATLAS_PRIVATE_KEY=<secret>
```

And then just run Prowler with the following command:

```bash
prowler mongodbatlas
```

### Scanning a Specific Project

If you want to scan a specific project, you can use the following argument added to the command above:

```bash
prowler mongodbatlas --atlas-project-id <project-id>
```
