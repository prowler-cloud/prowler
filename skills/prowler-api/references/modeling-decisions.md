# Django Model Design Decisions

## When to Use What

### Primary Keys

| Pattern | When to Use | Example |
|---------|-------------|---------|
| `uuid4` | Default for most models | `id = models.UUIDField(primary_key=True, default=uuid4)` |
| `uuid7` | Time-ordered data (findings, scans) | `id = models.UUIDField(primary_key=True, default=uuid7)` |

**Why uuid7 for time-series?** UUIDv7 includes timestamp, enabling efficient range queries and partitioning.

### Timestamps

| Field | Pattern | Purpose |
|-------|---------|---------|
| `inserted_at` | `auto_now_add=True, editable=False` | Creation time, never changes |
| `updated_at` | `auto_now=True, editable=False` | Last modification time |

### Soft Delete

```python
# Model
is_deleted = models.BooleanField(default=False)

# Custom manager (excludes deleted by default)
class ActiveProviderManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)

# Usage
objects = ActiveProviderManager()      # Normal queries
all_objects = models.Manager()         # Include deleted
```

### TextChoices Enums

```python
class StateChoices(models.TextChoices):
    AVAILABLE = "available", _("Available")
    SCHEDULED = "scheduled", _("Scheduled")
    EXECUTING = "executing", _("Executing")
    COMPLETED = "completed", _("Completed")
    FAILED = "failed", _("Failed")
```

### Constraints

| Constraint | When to Use |
|------------|-------------|
| `UniqueConstraint` | Prevent duplicates within tenant scope |
| `UniqueConstraint + condition` | Unique only for non-deleted records |
| `RowLevelSecurityConstraint` | ALL RLS-protected models (mandatory) |

```python
constraints = [
    # Unique provider UID per tenant (only for active providers)
    models.UniqueConstraint(
        fields=("tenant_id", "provider", "uid"),
        condition=Q(is_deleted=False),
        name="unique_provider_uids",
    ),
    # RLS constraint (REQUIRED for all tenant-scoped models)
    RowLevelSecurityConstraint(
        field="tenant_id",
        name="rls_on_%(class)s",
        statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
    ),
]
```

### Indexes

| Index Type | When to Use | Example |
|------------|-------------|---------|
| `models.Index` | Frequent queries | `fields=["tenant_id", "provider_id"]` |
| `GinIndex` | Full-text search, ArrayField | `fields=["text_search"]` |
| Conditional Index | Specific query patterns | `condition=Q(state="completed")` |
| Covering Index | Avoid table lookups | `include=["id", "name"]` |

```python
indexes = [
    # Common query pattern
    models.Index(
        fields=["tenant_id", "provider_id", "-inserted_at"],
        name="scans_prov_ins_desc_idx",
    ),
    # Conditional: only completed scans
    models.Index(
        fields=["tenant_id", "provider_id", "-inserted_at"],
        condition=Q(state=StateChoices.COMPLETED),
        name="scans_completed_idx",
    ),
    # Covering: include extra columns to avoid table lookup
    models.Index(
        fields=["tenant_id", "provider_id"],
        include=["id", "graph_database"],
        name="aps_active_graph_idx",
    ),
    # Full-text search
    GinIndex(fields=["text_search"], name="gin_resources_search_idx"),
]
```

### Full-Text Search

```python
from django.contrib.postgres.search import SearchVector, SearchVectorField

text_search = models.GeneratedField(
    expression=SearchVector("uid", weight="A", config="simple")
    + SearchVector("name", weight="B", config="simple"),
    output_field=SearchVectorField(),
    db_persist=True,
    null=True,
    editable=False,
)
```

### ArrayField

```python
from django.contrib.postgres.fields import ArrayField

groups = ArrayField(
    models.CharField(max_length=100),
    blank=True,
    null=True,
    help_text="Groups for categorization",
)
```

### JSONField

```python
# Structured data with defaults
metadata = models.JSONField(default=dict, blank=True)
scanner_args = models.JSONField(default=dict, blank=True)
```

### Encrypted Fields

```python
# Binary field for encrypted data
_secret = models.BinaryField(db_column="secret")

@property
def secret(self):
    # Decrypt on read
    decrypted_data = fernet.decrypt(self._secret)
    return json.loads(decrypted_data.decode())

@secret.setter
def secret(self, value):
    # Encrypt on write
    self._secret = fernet.encrypt(json.dumps(value).encode())
```

### Foreign Keys

| on_delete | When to Use |
|-----------|-------------|
| `CASCADE` | Child cannot exist without parent (Finding → Scan) |
| `SET_NULL` | Optional relationship, keep child (Task → PeriodicTask) |
| `PROTECT` | Prevent deletion if children exist |

```python
# Required relationship
provider = models.ForeignKey(
    Provider,
    on_delete=models.CASCADE,
    related_name="scans",
    related_query_name="scan",
)

# Optional relationship
scheduler_task = models.ForeignKey(
    PeriodicTask,
    on_delete=models.SET_NULL,
    null=True,
    blank=True,
)
```

### Many-to-Many with Through Table

```python
# On the model
tags = models.ManyToManyField(
    ResourceTag,
    through="ResourceTagMapping",
    related_name="resources",
)

# Through table (for RLS + extra fields)
class ResourceTagMapping(RowLevelSecurityProtectedModel):
    id = models.UUIDField(primary_key=True, default=uuid4)
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    tag = models.ForeignKey(ResourceTag, on_delete=models.CASCADE)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("tenant_id", "resource_id", "tag_id"),
                name="unique_resource_tag_mappings",
            ),
            RowLevelSecurityConstraint(...),
        ]
```

### Partitioned Tables

```python
from psqlextra.models import PostgresPartitionedModel
from psqlextra.types import PostgresPartitioningMethod

class Finding(PostgresPartitionedModel, RowLevelSecurityProtectedModel):
    class PartitioningMeta:
        method = PostgresPartitioningMethod.RANGE
        key = ["id"]  # UUIDv7 for time-based partitioning
```

**Use for:** High-volume, time-series data (findings, resource mappings)

### Model Validation

```python
def clean(self):
    super().clean()
    # Dynamic validation based on field value
    getattr(self, f"validate_{self.provider}_uid")(self.uid)

def save(self, *args, **kwargs):
    self.full_clean()  # Always validate before save
    super().save(*args, **kwargs)
```

### JSONAPIMeta

```python
class JSONAPIMeta:
    resource_name = "provider-groups"  # kebab-case, plural
```

---

## Decision Tree: New Model

```
Is it tenant-scoped data?
├── Yes → Inherit RowLevelSecurityProtectedModel
│         Add RowLevelSecurityConstraint
│         Consider: soft-delete? partitioning?
└── No → Regular models.Model (rare in Prowler)

Does it need time-ordering for queries?
├── Yes → Use uuid7 for primary key
└── No → Use uuid4 (default)

Is it high-volume time-series data?
├── Yes → Use PostgresPartitionedModel
│         Partition by id (uuid7)
└── No → Regular model

Does it reference Provider?
├── Yes → Add ActiveProviderManager
│         Use CASCADE or filter is_deleted
└── No → Standard manager

Needs full-text search?
├── Yes → Add SearchVectorField + GinIndex
└── No → Skip
```
