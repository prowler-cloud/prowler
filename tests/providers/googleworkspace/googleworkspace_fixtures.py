"""Test fixtures for Google Workspace provider tests"""

# Google Workspace test constants
DOMAIN = "test-company.com"
CUSTOMER_ID = "C1234567"
DELEGATED_USER = "prowler-reader@test-company.com"

# Service Account credentials (mock)
SERVICE_ACCOUNT_CREDENTIALS = {
    "type": "service_account",
    "project_id": "test-project-12345",
    "private_key_id": "test-key-id-12345",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----\n",
    "client_email": "test-sa@test-project-12345.iam.gserviceaccount.com",
    "client_id": "123456789012345678901",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-sa%40test-project-12345.iam.gserviceaccount.com",
}

# Mock user data
USER_1 = {
    "id": "user1-id",
    "primaryEmail": "admin@test-company.com",
    "name": {"fullName": "Admin User", "givenName": "Admin", "familyName": "User"},
    "isAdmin": True,
    "isDelegatedAdmin": False,
    "suspended": False,
    "archived": False,
    "creationTime": "2020-01-01T00:00:00.000Z",
    "lastLoginTime": "2024-01-01T00:00:00.000Z",
    "orgUnitPath": "/",
    "isMailboxSetup": True,
    "customerId": CUSTOMER_ID,
}

USER_2 = {
    "id": "user2-id",
    "primaryEmail": "admin2@test-company.com",
    "name": {"fullName": "Admin User 2", "givenName": "Admin", "familyName": "User 2"},
    "isAdmin": True,
    "isDelegatedAdmin": False,
    "suspended": False,
    "archived": False,
    "creationTime": "2020-01-01T00:00:00.000Z",
    "lastLoginTime": "2024-01-01T00:00:00.000Z",
    "orgUnitPath": "/",
    "isMailboxSetup": True,
    "customerId": CUSTOMER_ID,
}

USER_3 = {
    "id": "user3-id",
    "primaryEmail": "user@test-company.com",
    "name": {"fullName": "Regular User", "givenName": "Regular", "familyName": "User"},
    "isAdmin": False,
    "isDelegatedAdmin": False,
    "suspended": False,
    "archived": False,
    "creationTime": "2020-01-01T00:00:00.000Z",
    "lastLoginTime": "2024-01-01T00:00:00.000Z",
    "orgUnitPath": "/",
    "isMailboxSetup": True,
    "customerId": CUSTOMER_ID,
}
