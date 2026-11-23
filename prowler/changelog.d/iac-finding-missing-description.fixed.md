IaC scans no longer lose every finding with an `IacOutputProcessingError` when Trivy reports one without a `Description`, such as its `DIG-0008` check; the finding title is used instead
