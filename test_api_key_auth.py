#!/usr/bin/env python3

# Test script to debug API key authentication
import sys
import os

# Add the API backend to Python path
sys.path.insert(0, '/Users/martin/git/prowler/api/src/backend')

# Set Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.django.dev')

import django
django.setup()

from api.models import APIKey

# Test the API key components
api_key = "pk_lQG9tQJi.hbRrmKMJ45I20sHPnjY53OGLruiTA-Gy"
print(f"Testing API key: {api_key}")

# Test 1: Prefix extraction
try:
    prefix = APIKey.extract_prefix(api_key)
    print(f"✓ Prefix extracted successfully: {prefix}")
except Exception as e:
    print(f"✗ Prefix extraction failed: {e}")
    sys.exit(1)

# Test 2: Find candidate keys by prefix
try:
    candidate_keys = APIKey.all_objects.filter(prefix=prefix)
    count = candidate_keys.count()
    print(f"✓ Found {count} candidate keys with prefix '{prefix}'")
    
    if count > 0:
        for candidate in candidate_keys:
            print(f"  - Candidate ID: {candidate.id}")
            print(f"  - Candidate name: {candidate.name}")
            print(f"  - Candidate tenant: {candidate.tenant_id}")
            print(f"  - Key hash length: {len(candidate.key_hash)}")
    else:
        print("✗ No candidate keys found!")
        sys.exit(1)
        
except Exception as e:
    print(f"✗ Database query failed: {e}")
    sys.exit(1)

# Test 3: Key verification for each candidate
for candidate in candidate_keys:
    try:
        is_valid = APIKey.verify_key(api_key, candidate.key_hash)
        print(f"✓ Key verification for {candidate.id}: {is_valid}")
        
        if is_valid:
            print(f"✓ Found matching API key: {candidate.id}")
            
            # Test 4: Check if key is valid (not expired/revoked)
            if candidate.is_valid():
                print(f"✓ API key is valid (not expired/revoked)")
            else:
                if candidate.revoked_at:
                    print(f"✗ API key is revoked: {candidate.revoked_at}")
                else:
                    print(f"✗ API key is expired: {candidate.expires_at}")
        else:
            print(f"✗ Key verification failed for {candidate.id}")
            
    except Exception as e:
        print(f"✗ Key verification error: {e}")

print("Test completed.")
