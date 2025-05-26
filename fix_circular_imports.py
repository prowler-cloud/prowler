#!/usr/bin/env python3
import os
import shutil
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime

def make_backup(file_path: str) -> str:
    """Make a backup of a file with timestamp in the filename."""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{file_path}.{timestamp}.bak"
    shutil.copy2(file_path, backup_path)
    print(f"Created backup: {backup_path}")
    return backup_path

def fix_ionos_provider(file_path: str) -> None:
    """
    Fix the ionos_provider.py file by moving the IonosCompute import
    inside the get_compute method.
    """
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Remove the import from the top
    content = re.sub(
        r'from prowler\.providers\.ionos\.services\.compute\.compute_service import IonosCompute\n',
        '',
        content
    )
    
    # Add the import inside the get_compute method
    content = re.sub(
        r'(def get_compute\(self\).*?\n\s+)(.+)',
        r'\1from prowler.providers.ionos.services.compute.compute_service import IonosCompute\n        \2',
        content, 
        flags=re.DOTALL
    )
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Modified: {file_path}")

def fix_service_py(file_path: str) -> None:
    """
    Fix the lib/service.py file to use forward declarations for IonosProvider
    instead of importing it directly.
    """
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Remove the direct import
    content = re.sub(
        r'from prowler\.providers\.ionos\.ionos_provider import IonosProvider\n',
        '',
        content
    )
    
    # Add the TYPE_CHECKING import and forward declaration at the top
    if 'TYPE_CHECKING' not in content:
        import_section = re.search(r'import.*?\n\n', content, re.DOTALL)
        if import_section:
            improved_imports = import_section.group(0)
            improved_imports = improved_imports.rstrip() + "\nfrom typing import TYPE_CHECKING\n\n"
            
            if TYPE_CHECKING_block := "if TYPE_CHECKING:\n    from prowler.providers.ionos.ionos_provider import IonosProvider\n\n":
                content = content.replace(import_section.group(0), improved_imports + TYPE_CHECKING_block)
    
    # Replace IonosProvider with 'IonosProvider' (as string) in type hints
    content = re.sub(
        r'(.*?)IonosProvider([,\)\s])',
        r'\1"IonosProvider"\2',
        content
    )
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Modified: {file_path}")

def main():
    # Base directory where prowler is installed
    base_dir = "prowler"
    
    # Paths to the files we need to modify
    ionos_provider_path = os.path.join(base_dir, "providers", "ionos", "ionos_provider.py")
    service_py_path = os.path.join(base_dir, "providers", "ionos", "lib", "service.py")
    
    # Check if files exist
    if not os.path.exists(ionos_provider_path):
        print(f"Error: {ionos_provider_path} not found")
        return
    
    if not os.path.exists(service_py_path):
        print(f"Error: {service_py_path} not found")
        return
    
    # Make backups before modifying
    make_backup(ionos_provider_path)
    make_backup(service_py_path)
    
    # Fix the files
    fix_ionos_provider(ionos_provider_path)
    fix_service_py(service_py_path)
    
    print("\nFiles have been modified to fix the circular import problem.")
    print("Please test your application to ensure everything works as expected.")

if __name__ == "__main__":
    main()

