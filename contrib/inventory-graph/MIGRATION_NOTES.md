# Migration Notes: Inventory Graph to /contrib

This document explains the changes made to move the AWS Inventory Connectivity Graph feature from core Prowler to the `/contrib` folder as requested by maintainers.

## Summary of Changes

### What Changed

1. **Module Location**
   - **Before:** `prowler/lib/outputs/inventory/`
   - **After:** `contrib/inventory-graph/lib/`

2. **Integration with Prowler**
   - **Before:** Integrated as `--output-formats inventory-graph` in core Prowler
   - **After:** Standalone tool that can be run independently after a Prowler scan

3. **Import Paths**
   - Updated all imports from `prowler.lib.outputs.inventory.*` to relative imports (`lib.*`)
   - Extractor registry updated to use new module paths

### Files Added

- `contrib/inventory-graph/README.md` - Comprehensive documentation
- `contrib/inventory-graph/inventory_graph.py` - Standalone entry point script
- `contrib/inventory-graph/examples/example_usage.py` - Example with mock data
- `contrib/inventory-graph/MIGRATION_NOTES.md` - This file

### Files Moved

All files from `prowler/lib/outputs/inventory/` moved to `contrib/inventory-graph/lib/`:
- `models.py`
- `graph_builder.py`
- `inventory_output.py`
- `extractors/__init__.py`
- `extractors/lambda_extractor.py`
- `extractors/ec2_extractor.py`
- `extractors/vpc_extractor.py`
- `extractors/rds_extractor.py`
- `extractors/elbv2_extractor.py`
- `extractors/s3_extractor.py`
- `extractors/iam_extractor.py`

### Files Modified

1. **prowler/config/config.py**
   - Removed: `inventory_graph_file_suffix = ".inventory"`
   - Removed: `"inventory-graph"` from `available_output_formats`

2. **prowler/__main__.py**
   - Removed: `inventory_graph_file_suffix` import
   - Removed: `if mode == "inventory-graph":` block and its handler

3. **prowler/CHANGELOG.md**
   - Updated entry to reflect contrib status

## How to Use (After Migration)

### Previous Usage (Before Migration)
```bash
prowler aws --output-formats inventory-graph
```

### New Usage (After Migration)

**Option 1: Run as standalone script**
```bash
# Run Prowler scan first
prowler aws --output-formats csv html

# Then generate inventory graph
python contrib/inventory-graph/inventory_graph.py \
  --output-directory ./output \
  --output-filename my-inventory
```

**Option 2: Integrate into custom workflows**
```python
from contrib.inventory_graph.lib.graph_builder import build_graph
from contrib.inventory_graph.lib.inventory_output import write_json, write_html

# After Prowler scan completes
graph = build_graph()
write_json(graph, "output/inventory.json")
write_html(graph, "output/inventory.html")
```

## Benefits of This Approach

1. **Non-invasive** - No changes to core Prowler code
2. **Maintainable** - Community can enhance without affecting core
3. **Flexible** - Can be used standalone or integrated into custom workflows
4. **Clear separation** - Contrib features are clearly identified
5. **Backward compatible** - Core Prowler functionality unchanged

## For Users Upgrading

If you were using `--output-formats inventory-graph` in previous versions:

1. Update your scripts to remove `inventory-graph` from output formats
2. Add a separate step to run the inventory graph tool:
   ```bash
   prowler aws --output-formats csv html
   python contrib/inventory-graph/inventory_graph.py
   ```

## For Contributors

To enhance this tool:

1. All changes should be made in `contrib/inventory-graph/`
2. Follow the existing code structure
3. Update README.md with new features
4. Add examples if introducing new functionality
5. Test with mock data using `examples/example_usage.py`

## Technical Details

### Import Path Changes

**Before:**
```python
from prowler.lib.outputs.inventory.models import ResourceNode
from prowler.lib.outputs.inventory.graph_builder import build_graph
```

**After:**
```python
from lib.models import ResourceNode
from lib.graph_builder import build_graph
```

### Extractor Registry Changes

**Before:**
```python
"prowler.lib.outputs.inventory.extractors.lambda_extractor"
```

**After:**
```python
"lib.extractors.lambda_extractor"
```

## Questions?

For questions or issues:
- Open an issue in the [Prowler repository](https://github.com/prowler-cloud/prowler/issues)
- Tag with `contrib:inventory-graph`
- Join [Prowler Community Slack](https://goto.prowler.com/slack)

## Related

- Original PR: [#10382](https://github.com/prowler-cloud/prowler/pull/10382)
- Maintainer request: [Comment](https://github.com/prowler-cloud/prowler/pull/10382#issuecomment-4379080898)
