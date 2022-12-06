## K8S - Cronjob
Simple instructions to add a cronjob on K8S to execute a prowler and save the results on AWS S3.

### Files:
cronjob.yml ---> is a **cronjob** for K8S, you must set the frequency and probes from yours scans \
secret.yml -----> is a **secret** file with AWS ID/Secret and the name of bucket

### To apply:

`$ kubectl -f cronjob.yml` \
`$ kubectl -f secret.yml`
