# StackIT Provider Implementation - TODO

## Current Status

The StackIT provider has been successfully integrated into Prowler with critical security checks!

### ✅ Completed
1. Created provider directory structure and core files
2. Implemented StackITProvider class with API token authentication
3. Added StackIT arguments (--stackit-api-token, --stackit-project-id)
4. Added CheckReportStackIT model
5. Registered provider in common/provider.py
6. Added StackIT support in __main__.py, summary_table.py, finding.py, and outputs.py
7. Created compliance directory structure
8. Bumped Python minimum version to 3.10+ to support stackit-core SDK
9. Added stackit-core, stackit-iaas, and stackit-objectstorage dependencies to pyproject.toml
10. Fixed SDK imports (DefaultApi takes Configuration directly)
11. Fixed Configuration authentication (uses STACKIT_SERVICE_ACCOUNT_TOKEN env var)
12. Fixed output generation (added StackIT support in stdout_report)
13. Implemented IaaS service with security group discovery
14. Implemented 4 critical security group checks:
    - iaas_security_group_ssh_unrestricted (port 22)
    - iaas_security_group_rdp_unrestricted (port 3389)
    - iaas_security_group_database_unrestricted (MySQL, PostgreSQL, MongoDB, Redis, SQL Server, CouchDB)
    - iaas_security_group_all_traffic_unrestricted (all ports/protocols)

### ✅ Latest Changes (Commit: 4ab5389)

**Replaced objectstorage service with iaas service**
- Removed objectstorage_bucket_encryption check (encryption enabled by default)
- Created IaaSService class for security group operations
- Added stackit-iaas>=0.1.0 dependency
- Implemented 4 CRITICAL severity security group checks
- All checks focus on ingress TCP rules from 0.0.0.0/0 or ::/0

## Next Steps

### 1. Test the IaaS Security Group Checks

**Test Command**:
```bash
prowler stackit --stackit-api-token <token> --stackit-project-id <project-id>
```

**Expected Behavior**:
- Successfully authenticate with StackIT API
- Discover security groups in the project
- Execute all 4 security group checks
- Generate findings for any insecure rules

### 2. Potential Issues to Watch For

**Possible Issues**:
- SDK import errors if `stackit-iaas` package not installed
- API method signature differences from documentation
- Response parsing issues (security groups/rules structure)
- Region parameter requirements
- Port range handling edge cases

**Debugging Commands**:
```python
# Test SDK imports
from stackit.iaas import DefaultApi
from stackit.core.configuration import Configuration

# Test API calls
import os
os.environ["STACKIT_SERVICE_ACCOUNT_TOKEN"] = "your-token"
config = Configuration()
client = DefaultApi(config)
response = client.list_security_groups(project_id="your-project", region="eu01")
```

### 3. Future Enhancements

**Additional Checks to Consider**:
- iaas_server_public_ip_exposed - Check if VMs have public IPs
- iaas_network_isolated - Check if networks are properly segmented
- iaas_volume_encrypted - Check if storage volumes are encrypted
- iaas_server_backup_enabled - Check if backups are configured

**Multi-Region Support**:
- Currently hardcoded to "eu01" region
- Add --stackit-region argument to support eu01/eu02
- Loop through all regions when discovering resources

**Code Quality Improvements**:
- Add unit tests for IaaSService
- Add integration tests with mock API responses
- Improve error handling for specific API errors
- Add retry logic for transient failures

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
