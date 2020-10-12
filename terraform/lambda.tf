data "archive_file" "lambda_zip_inline" {
  type        = "zip"
  output_path = "/tmp/lambda_zip.zip"
  source_dir = "build"
}

resource "aws_cloudwatch_log_group" "logs" {
  name              = "/aws/lambda/iam-alert-disable"
  retention_in_days = 1
}

resource "aws_lambda_function" "lambda" {
  filename      = data.archive_file.lambda_zip_inline.output_path
  source_code_hash = data.archive_file.lambda_zip_inline.output_base64sha256
  function_name = "iam-alert-disable"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "handler.handler"
  timeout = 120

  runtime = "python3.8"

  environment {
    variables = {
      LOG_LEVEL = "INFO"
      EMAIL_TAG_NAME = "email"
      SELECTION_TAG_NAME = "email"
      ALERT_THRESHOLDS = "0, 1"
      DISABLE_THRESHOLD = "2"
      EMAIL_SENDER = local.ses_email_sender
      SKIP_TAG = "skip-cleanup=true"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_logs,
    aws_cloudwatch_log_group.logs,
  ]
}

resource "aws_cloudwatch_event_rule" "trigger" {
  name                = "iam-alert-lambda-trigger"
  description         = "Fires every day"
  schedule_expression = "rate(1 day)"
  is_enabled = false
}

resource "aws_cloudwatch_event_target" "check_foo_every_one_minute" {
  rule      = "${aws_cloudwatch_event_rule.trigger.name}"
  target_id = "lambda"
  arn       = "${aws_lambda_function.lambda.arn}"
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_check_foo" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.lambda.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.trigger.arn}"
}