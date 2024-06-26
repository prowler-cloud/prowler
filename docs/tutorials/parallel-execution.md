# Parallel Execution

The strategy used here will be to execute Prowler once per service. You can modify this approach as per your requirements.

This can help for really large accounts, but please be aware of AWS API rate limits:

1. **Service-Specific Limits**: Each AWS service has its own rate limits. For instance, Amazon EC2 might have different rate limits for launching instances versus making API calls to describe instances.
2. **API Rate Limits**: Most of the rate limits in AWS are applied at the API level. Each API call to an AWS service counts towards the rate limit for that service.
3. **Throttling Responses**: When you exceed the rate limit for a service, AWS responds with a throttling error. In AWS SDKs, these are typically represented as `ThrottlingException` or `RateLimitExceeded` errors.

For information on Prowler's retrier configuration please refer to this [page](https://docs.prowler.cloud/en/latest/tutorials/aws/boto3-configuration/).

???+ note
    You might need to increase the `--aws-retries-max-attempts` parameter from the default value of 3. The retrier follows an exponential backoff strategy.

## Linux

Generate a list of services that Prowler supports, and populate this info into a file:

```bash
prowler aws --list-services | awk -F"- " '{print $2}' | sed '/^$/d' > services
```

Make any modifications for services you would like to skip scanning by modifying this file.

Then create a new PowerShell script file `parallel-prowler.sh` and add the following contents. Update the `$profile` variable to the AWS CLI profile you want to run Prowler with.

```bash
#!/bin/bash

# Change these variables as needed
profile="your_profile"
account_id=$(aws sts get-caller-identity --profile "${profile}" --query 'Account' --output text)

echo "Executing in account: ${account_id}"

# Maximum number of concurrent processes
MAX_PROCESSES=5

# Loop through the services
while read service; do
    echo "$(date '+%Y-%m-%d %H:%M:%S'): Starting job for service: ${service}"

    # Run the command in the background
    (prowler -p "$profile" -s "$service" -F "${account_id}-${service}"  --only-logs; echo "$(date '+%Y-%m-%d %H:%M:%S') - ${service} has completed") &

    # Check if we have reached the maximum number of processes
    while [ $(jobs -r | wc -l) -ge ${MAX_PROCESSES} ]; do
        # Wait for a second before checking again
        sleep 1
    done
done < ./services

# Wait for all background processes to finish
wait
echo "All jobs completed"
```

Output will be stored in the `output/` folder that is in the same directory from which you executed the script.

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

Make any modifications for services you would like to skip scanning by modifying this file.

Then create a new PowerShell script file `parallel-prowler.ps1` and add the following contents. Update the `$profile` variable to the AWS CLI profile you want to run prowler with.

Change any parameters you would like when calling prowler in the `Start-Job -ScriptBlock` section. Note that you need to keep the `--only-logs` parameter, else some encoding issue occurs when trying to render the progress-bar and prowler won't successfully execute.

```powershell
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
        prowler -p ${using:profile} -s ${using:service} -F "${using:account_id}-${using:service}" --only-logs
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

Output will be stored in `C:\Users\YOUR-USER\Documents\output\`

## Combining the output files

Guidance is provided for the CSV file format. From the ouput directory, execute either the following Bash or PowerShell script. The script will collect the output from the CSV files, only include the header from the first file, and then output the result as CombinedCSV.csv in the current working directory.

There is no logic implemented in terms of which CSV files it will combine. If you have additional CSV files from other actions, such as running a quick inventory, you will need to move that out of the current (or any nested) directory, or move the output you want to combine into its own folder and run the script from there.

```bash
#!/bin/bash

# Initialize a variable to indicate the first file
firstFile=true

# Find all CSV files and loop through them
find . -name "*.csv" -print0 | while IFS= read -r -d '' file; do
    if [ "$firstFile" = true ]; then
        # For the first file, keep the header
        cat "$file" > CombinedCSV.csv
        firstFile=false
    else
        # For subsequent files, skip the header
        tail -n +2 "$file" >> CombinedCSV.csv
    fi
done
```

```powershell
# Get all CSV files from current directory and its subdirectories
$csvFiles = Get-ChildItem -Recurse -Filter "*.csv"

# Initialize a variable to track if it's the first file
$firstFile = $true

# Loop through each CSV file
foreach ($file in $csvFiles) {
    if ($firstFile) {
        # For the first file, keep the header and change the flag
        $combinedCsv = Import-Csv -Path $file.FullName
        $firstFile = $false
    } else {
        # For subsequent files, skip the header
        $tempCsv = Import-Csv -Path $file.FullName
        $combinedCsv += $tempCsv | Select-Object * -Skip 1
    }
}

# Export the combined data to a new CSV file
$combinedCsv | Export-Csv -Path "CombinedCSV.csv" -NoTypeInformation
```

## TODO: Additional Improvements

Some services need to instantiate another service to perform a check. For instance, `cloudwatch` will instantiate Prowler's `iam` service to perform the `cloudwatch_cross_account_sharing_disabled` check. When the `iam` service is instantiated, it will perform the `__init__` function, and pull all the information required for that service. This provides an opportunity for an improvement in the above script to group related services together so that the `iam` services (or any other cross-service references) isn't repeatedily instantiated by grouping dependant services together. A complete mapping between these services still needs to be further investigated, but these are the cross-references that have been noted:

* inspector2 needs lambda and ec2
* cloudwatch needs iam
* dlm needs ec2
