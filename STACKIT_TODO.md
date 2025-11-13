# StackIT Provider Implementation - TODO

## Current Status

The StackIT provider has been successfully integrated into Prowler with the following completed items:

### ✅ Completed
1. Created provider directory structure and core files
2. Implemented StackITProvider class with API token authentication
3. Added StackIT arguments (--stackit-api-token, --stackit-project-id)
4. Created ObjectStorage service with bucket listing and encryption check
5. Implemented objectstorage_bucket_encryption check
6. Added CheckReportStackIT model
7. Registered provider in common/provider.py
8. Added StackIT support in __main__.py, summary_table.py, and finding.py
9. Created compliance directory structure
10. Bumped Python minimum version to 3.10+ to support stackit-core SDK
11. Added stackit-core and stackit-objectstorage dependencies to pyproject.toml
12. Fixed SDK imports (DefaultApi instead of ObjectStorageClient)
13. Fixed Configuration import path (stackit.core.configuration.Configuration)
14. Fixed Configuration parameters (removed project_id from init)

### ❌ Current Issue

**Error**: `'ApiClient' object has no attribute 'custom_endpoint'`

**Location**: `prowler/providers/stackit/services/objectstorage/objectstorage_service.py:62`

**Root Cause**: The ApiClient needs additional configuration or the endpoint needs to be set in the Configuration object before creating the ApiClient.

## Plan for Tomorrow

### 1. Research StackIT SDK Endpoint Configuration

**Goal**: Understand how to properly configure the API endpoint for Object Storage

**Tasks**:
- [ ] Check if `Configuration` needs `custom_endpoint` parameter set
- [ ] Research the default endpoint for StackIT Object Storage API
- [ ] Look at stackit-objectstorage examples in the SDK repository
- [ ] Check what the `custom_endpoint` should be for Object Storage

**Expected Endpoint Format**: Likely something like:
- `https://objectstorage.api.eu01.stackit.cloud` or
- `https://api.stackit.cloud/objectstorage/v1` or
- Similar pattern based on StackIT API structure

**Investigation Commands**:
```python
from stackit.objectstorage import ApiClient
import inspect
print(inspect.getsource(ApiClient.__init__))
```

```python
from stackit.core.configuration import Configuration
config = Configuration(service_account_token="dummy")
print(dir(config))
print(config.__dict__)
```

### 2. Fix ApiClient Initialization

**Current Code** (`objectstorage_service.py:39-53`):
```python
config = Configuration(
    service_account_token=self.api_token,
)

api_client = ApiClient(config)
client = DefaultApi(api_client)
```

**Likely Fix Option 1** - Add custom_endpoint to Configuration:
```python
config = Configuration(
    service_account_token=self.api_token,
    custom_endpoint="https://objectstorage.api.eu01.stackit.cloud",  # TBD: Find correct endpoint
)

api_client = ApiClient(config)
client = DefaultApi(api_client)
```

**Likely Fix Option 2** - Set endpoint on ApiClient:
```python
config = Configuration(
    service_account_token=self.api_token,
)

api_client = ApiClient(config)
api_client.configuration.host = "https://objectstorage.api.eu01.stackit.cloud"  # TBD
client = DefaultApi(api_client)
```

**Files to Update**:
- `prowler/providers/stackit/services/objectstorage/objectstorage_service.py:39-53`
- `prowler/providers/stackit/stackit_provider.py:307-322` (test_connection method)

### 3. Test the Fix

**Test Command**:
```bash
prowler stackit --stackit-api-token <token> --stackit-project-id <project-id>
```

**Expected Behavior**:
- No more "custom_endpoint" errors
- Successfully list buckets from StackIT Object Storage
- Display encryption status for each bucket
- Generate findings for buckets without encryption

### 4. Handle Potential Additional Issues

**Possible Next Issues**:
- API method signature mismatch (e.g., how to call `list_buckets()`)
- Response parsing issues (buckets attribute structure)
- Encryption check API method name or parameters
- Region/location extraction from bucket data

**Debugging Strategy**:
- Add verbose logging to see API responses
- Print bucket data structure when received
- Check SDK documentation for correct API method signatures

### 5. Code Quality Improvements

Once the basic functionality works:

- [ ] Add error handling for specific StackIT API errors
- [ ] Add retry logic for transient failures
- [ ] Improve logging messages
- [ ] Add unit tests for ObjectStorage service
- [ ] Add integration test example
- [ ] Update documentation/README

## Key Information

### StackIT SDK Modules
- `stackit.core.configuration.Configuration` - SDK configuration
- `stackit.objectstorage.ApiClient` - API client wrapper
- `stackit.objectstorage.DefaultApi` - Object Storage API methods

### Configuration Parameters (from inspection)
```python
Configuration(
    region=None,
    service_account_mail=None,
    service_account_token=None,  # ✅ We use this
    service_account_key=None,
    service_account_key_path=None,
    private_key=None,
    private_key_path=None,
    credentials_file_path=None,
    custom_endpoint=None,        # ⚠️ Might need this
    custom_token_endpoint=None,
    custom_http_session=None,
    custom_auth=None,
    server_index=None
)
```

### ApiClient Parameters
```python
ApiClient(
    configuration,      # Required - Configuration object
    header_name=None,
    header_value=None,
    cookie=None
)
```

## Resources

- **StackIT Python SDK**: https://github.com/stackitcloud/stackit-sdk-python
- **StackIT API Docs**: https://docs.api.eu01.stackit.cloud/
- **PyPI stackit-objectstorage**: https://pypi.org/project/stackit-objectstorage/
- **PyPI stackit-core**: https://pypi.org/project/stackit-core/

## Notes

- The SDK is still in pre-release (0.0.1a0 for objectstorage)
- May need to check SDK source code for proper usage
- Consider reaching out to StackIT support if documentation is unclear
- Keep Python version at >=3.10 for urllib3 2.x compatibility
