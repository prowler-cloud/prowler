### Added
- Default JWT keys are generated and stored if they are missing from configuration [(#8655)](https://github.com/prowler-cloud/prowler/pull/8655)
- `compliance_name` for each compliance [(#7920)](https://github.com/prowler-cloud/prowler/pull/7920)
- Support C5 compliance framework for the AWS provider [(#8830)](https://github.com/prowler-cloud/prowler/pull/8830)
- Support for M365 Certificate authentication [(#8538)](https://github.com/prowler-cloud/prowler/pull/8538)
- API Key support [(#8805)](https://github.com/prowler-cloud/prowler/pull/8805)
- SAML role mapping protection for single-admin tenants to prevent accidental lockout [(#8882)](https://github.com/prowler-cloud/prowler/pull/8882)
- Support for `passed_findings` and `total_findings` fields in compliance requirement overview for accurate Prowler ThreatScore calculation [(#8582)](https://github.com/prowler-cloud/prowler/pull/8582)
- PDF reporting for Prowler ThreatScore [(#8867)](https://github.com/prowler-cloud/prowler/pull/8867)
- Database read replica support [(#8869)](https://github.com/prowler-cloud/prowler/pull/8869)
- Support Common Cloud Controls for AWS, Azure and GCP [(#8000)](https://github.com/prowler-cloud/prowler/pull/8000)
- Add `provider_id__in` filter support to findings and findings severity overview endpoints [(#8951)](https://github.com/prowler-cloud/prowler/pull/8951)
### Changed
- Now the MANAGE_ACCOUNT permission is required to modify or read user permissions instead of MANAGE_USERS [(#8281)](https://github.com/prowler-cloud/prowler/pull/8281)
- Now at least one user with MANAGE_ACCOUNT permission is required in the tenant [(#8729)](https://github.com/prowler-cloud/prowler/pull/8729)
### Security
- Django updated to the latest 5.1 security release, 5.1.13, due to problems with potential [SQL injection](https://github.com/prowler-cloud/prowler/security/dependabot/104) and [directory traversals](https://github.com/prowler-cloud/prowler/security/dependabot/103) [(#8842)](https://github.com/prowler-cloud/prowler/pull/8842)
