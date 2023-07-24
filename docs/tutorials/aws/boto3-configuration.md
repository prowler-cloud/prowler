# Boto3 Retrier Configuration

Prowler's AWS Provider uses the Boto3 [Standard](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html) retry mode to assist in retrying client calls to AWS services when these kinds of errors or exceptions are experienced. This mode includes the following behaviours:

- A default value of 3 for maximum retry attempts. This can be overwritten with the `--aws-retries-max-attempts 5` argument.

- Retry attempts for an expanded list of errors/exceptions:
    ```
    # Transient errors/exceptions
    RequestTimeout
    RequestTimeoutException
    PriorRequestNotComplete
    ConnectionError
    HTTPClientError

    # Service-side throttling/limit errors and exceptions
    Throttling
    ThrottlingException
    ThrottledException
    RequestThrottledException
    TooManyRequestsException
    ProvisionedThroughputExceededException
    TransactionInProgressException
    RequestLimitExceeded
    BandwidthLimitExceeded
    LimitExceededException
    RequestThrottled
    SlowDown
    EC2ThrottledException
    ```

- Retry attempts on nondescriptive, transient error codes. Specifically, these HTTP status codes: 500, 502, 503, 504.

- Any retry attempt will include an exponential backoff by a base factor of 2 for a maximum backoff time of 20 seconds.
