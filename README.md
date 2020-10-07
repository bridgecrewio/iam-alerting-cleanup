# IAM User Alerting and Cleanup Tool

This tool scans IAM users for unused credentials (console passwords and access keys), sends alerts based on configurable thresholds, and disables them after a configurable threshold.

Setup:

```shell script
pipenv install
```

Deploy Lambda with Terraform:
```shell script
./build.sh
```
