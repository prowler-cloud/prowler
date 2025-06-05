# Boto3 Retrier Configuration in Prowler

Prowler's AWS Provider leverages Boto3's[Standard](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html) retry mode to automatically retry client calls to AWS services when encountering errors or exceptions.

## Retry Behavior Overview

Boto3's Standard retry mode includes the following mechanisms:

- Maximum Retry Attempts: Default value set to 3, configurable via the `--aws-retries-max-attempts 5` argument.

- Expanded Error Handling: Retries occur for a comprehensive set of errors.

  ```
  # *Transient Errors/Exceptions*
  The retrier handles various temporary failures:
  RequestTimeout
  RequestTimeoutException
  PriorRequestNotComplete
  ConnectionError
  HTTPClientError

  # *Service-Side Throttling and Limit Errors*
  Retries occur for service-imposed rate limits and resource constraints:
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

- Nondescriptive Transient Error Codes: The retrier applies retry logic to standard HTTP status codes signaling transient errors: 500, 502, 503, 504.

- Exponential Backoff Strategy: Each retry attempt follows exponential backoff with a base factor of 2, ensuring progressive delay between retries. Maximum backoff time: 20 seconds

## Validating Retry Attempts

For testing or modifying Prowler's behavior, use the following steps to confirm whether requests are being retried or abandoned:

* Run prowler with `--log-level DEBUG` and `--log-file debuglogs.txt`
* Search for retry attempts using `grep -i 'Retry needed' debuglogs.txt`

This approach follows the [AWS documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html#checking-retry-attempts-in-your-client-logs), which states that if a retry is performed, a message starting with "Retry needed” will be prompted.

It is possible to determine the total number of calls made using `grep -i 'Sending http request' debuglogs.txt | wc -l`
