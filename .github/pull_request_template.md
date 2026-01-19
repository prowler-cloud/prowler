### Context

Please include relevant motivation and context for this PR.

If fixes an issue please add it with `Fix #XXXX`

### Description

Please include a summary of the change and which issue is fixed. List any dependencies that are required for this change.

### Steps to review

Please add a detailed description of how to review this PR.

### Checklist

<details>

<summary><b>Community Checklist</b></summary>

- [ ] This feature/issue is listed in [here](https://github.com/prowler-cloud/prowler/issues?q=sort%3Aupdated-desc+is%3Aissue+is%3Aopen) or roadmap.prowler.com
- [ ] Is it assigned to me, if not, request it via the issue/feature in [here](https://github.com/prowler-cloud/prowler/issues?q=sort%3Aupdated-desc+is%3Aissue+is%3Aopen) or [Prowler Community Slack](goto.prowler.com/slack)

</details>


- [ ] Review if the code is being covered by tests.
- [ ] Review if code is being documented following this specification https://github.com/google/styleguide/blob/gh-pages/pyguide.md#38-comments-and-docstrings
- [ ] Review if backport is needed.
- [ ] Review if is needed to change the [Readme.md](https://github.com/prowler-cloud/prowler/blob/master/README.md)
- [ ] Ensure new entries are added to [CHANGELOG.md](https://github.com/prowler-cloud/prowler/blob/master/prowler/CHANGELOG.md), if applicable.

#### SDK/CLI
- Are there new checks included in this PR? Yes / No
    - If so, do we need to update permissions for the provider? Please review this carefully.

#### UI
- [ ] All issue/task requirements work as expected on the UI
- [ ] Screenshots/Video of the functionality flow (if applicable) - Mobile (X < 640px)
- [ ] Screenshots/Video of the functionality flow (if applicable) - Table (640px > X < 1024px)
- [ ] Screenshots/Video of the functionality flow (if applicable) - Desktop (X > 1024px)
- [ ] Ensure new entries are added to [CHANGELOG.md](https://github.com/prowler-cloud/prowler/blob/master/ui/CHANGELOG.md), if applicable.

#### API
- [ ] All issue/task requirements work as expected on the API
- [ ] Endpoint response output (if applicable)
- [ ] EXPLAIN ANALYZE output for new/modified queries or indexes (if applicable)
- [ ] Performance test results (if applicable)
- [ ] Any other relevant evidence of the implementation (if applicable)
- [ ] Verify if API specs need to be regenerated.
- [ ] Check if version updates are required (e.g., specs, Poetry, etc.).
- [ ] Ensure new entries are added to [CHANGELOG.md](https://github.com/prowler-cloud/prowler/blob/master/api/CHANGELOG.md), if applicable.

### License

By submitting this pull request, I confirm that my contribution is made under the terms of the Apache 2.0 license.
