
The strategy used here will be to execute prowler once per service. You can modify this approach as per your requirements.

This can help for really large accounts, but please be aware of AWS API rate limits:

1. Service-Specific Limits: Each AWS service has its own rate limits. For instance, Amazon EC2 might have different rate limits for launching instances versus making API calls to describe instances.
2. API Rate Limits: Most of the rate limits in AWS are applied at the API level. Each API call to an AWS service counts towards the rate limit for that service.
3. Throttling Responses: When you exceed the rate limit for a service, AWS responds with a throttling error. In AWS SDKs, these are typically represented as ThrottlingException or RateLimitExceeded errors.

For information on Prowler's retrier configuration please refer to this [page](https://docs.prowler.cloud/en/latest/tutorials/aws/boto3-configuration/)

## Linux

Generate a list of services that Prowler supports, and populate this info into a file:

```bash
prowler aws --list-services | awk -F"- " '{print $2}' | sed '/^$/d' > services
```

Create a new PowerShell script file (`parallel-prowler.sh`) and add the following contents. Update the `$profile` variable to the AWS CLI profile you want to run prowler with.

```bash
#!/bin/bash

# Change these variables as needed
profile="your_profile"
account_id=$(aws sts get-caller-identity --profile $profile --query 'Account' --output text)

echo "Executing in account: $account_id"

# Maximum number of concurrent processes
MAX_PROCESSES=5

# Loop through the services
while read service; do
    echo "$(date '+%Y-%m-%d %H:%M:%S'): Starting job for service: $service"

    # Run the command in the background and capture its PID
    (prowler -p "$profile" -s "$service" -F "$account_id-$service" --ignore-unused-services --only-logs; echo "$(date '+%Y-%m-%d %H:%M:%S') - $service has completed") &

    # Check if we have reached the maximum number of processes
    while [ $(jobs -r | wc -l) -ge $MAX_PROCESSES ]; do
        # Wait for a second before checking again
        sleep 1
    done
done < services

# Wait for all background processes to finish
wait
echo "All jobs completed"
```
Execute the script: `bash parallel-prowler.sh`

Your output will be in the `output/` folder that is in the same directory from which you executed the script.

## Windows

Generate a list of services that Prowler supports, and populate this info into a file:

```powershell
prowler aws --list-services | ForEach-Object {
    # Capture lines that are likely service names
    if ($_ -match '^\- \w+$') {
        $_.Trim().Substring(2)
    }
} | Where-Object {
    # Filter out empty or null lines
    $_ -ne $null -and $_ -ne ''
} | Set-Content -Path "services"
```

Create a new PowerShell script file (`parallel-prowler.ps1`) and add the following contents. Update the `$profile` variable to the AWS CLI profile you want to run prowler with.

Change any parameters you would like when calling prowler in the `Start-Job -ScriptBlock` section. Note that you need to keep the `--only-logs` parameter, else some encoding issue occurs when trying to render the progress-bar and prowler won't successfully execute.

```
$profile = "your_profile"
$account_id = Invoke-Expression -Command "aws sts get-caller-identity --profile $profile --query 'Account' --output text"

Write-Host "Executing Prowler in $account_id"

# Maximum number of concurrent jobs
$MAX_PROCESSES = 5

# Read services from a file
$services = Get-Content -Path "services"

# Array to keep track of started jobs
$jobs = @()

foreach ($service in $services) {
    # Start the command as a job
    $job = Start-Job -ScriptBlock {
        prowler -p ${using:profile} -s ${using:service} -F "${using:account_id}-${using:service}" --ignore-unused-services --only-logs | Out-Null
	      $endTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Output "${endTimestamp} - $using:service has completed"
    }
    $jobs += $job
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Starting job for service: $service"

    # Check if we have reached the maximum number of jobs
    while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MAX_PROCESSES) {
        Start-Sleep -Seconds 1
        # Check for any completed jobs and receive their output
        $completedJobs = $jobs | Where-Object { $_.State -eq 'Completed' }
        foreach ($completedJob in $completedJobs) {
            Receive-Job -Job $completedJob -Keep | ForEach-Object { Write-Host $_ }
            $jobs = $jobs | Where-Object { $_.Id -ne $completedJob.Id }
            Remove-Job -Job $completedJob
        }
    }
}

# Check for any remaining completed jobs
$remainingCompletedJobs = $jobs | Where-Object { $_.State -eq 'Completed' }
foreach ($remainingJob in $remainingCompletedJobs) {
    Receive-Job -Job $remainingJob -Keep | ForEach-Object { Write-Host $_ }
    Remove-Job -Job $remainingJob
}

Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - All jobs completed"
```

Outputs will be stored in `C:\Users\YOUR-USER\Documents\output`
