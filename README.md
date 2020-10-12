# IAM User Alerting and Cleanup Tool

This tool scans IAM users for unused credentials (console passwords and access keys), sends alerts based on configurable thresholds, and disables them after a configurable threshold.

## Setup:

```shell script
pipenv install
```

## Deploy Lambda with Terraform:
```shell script
./build.sh
```

## Use:

### Variables
Set the following Lambda environment variables in lambda.tf:

* LOG_LEVEL - the log level (DEBUG, INFO, WARNING, ERROR). Optional; defaults to INFO.
* EMAIL_TAG_NAME - the name of the tag on users containing the email address. And IAM user that does not have this tag will not be processed. Required.
* SELECTION_TAG_NAME - the name of the tag that must appear on an IAM user in order to process them. This can be the same as the email tag name if a distinct tag is not needed. Required.
* SKIP_TAG - the key and value of a tag that indicates an IAM user should be skipped, even if they are matched by the email and selection tag. The format must be "TagName=TagValue". Optional.
* ALERT_THRESHOLDS - a comma-separated list of days after which to send alerts to users. Each time a credential exceeds a new threshold, the user will receive an alert email. Example: "60, 75, 85, 89". Required.
* DISABLE_THRESHOLD - the number of days after which an unused credential will be disabled. Example: "90". Required.
* EMAIL_SENDER - the display name and email address of the user from which to send emails. Example: "IT Eng <noreply@address.com>". Required.
* ACCOUNT_ALIAS - a user-friendly alias for the AWS account to be used in email subject lines. Optional; defaults to account ID.

### Execution

The Lambda function is triggered on a schedule defined by `aws_cloudwatch_event_rule.trigger`. It is set to `is_enabled = false` by default. The default frequency is 1 day.

### Email sending

The default setup uses AWS SES to send emails. See https://aws.amazon.com/getting-started/hands-on/send-an-email/ for simple setup instructions. In sandbox mode, this requires the source email and all recipient emails to be verified addresses.
