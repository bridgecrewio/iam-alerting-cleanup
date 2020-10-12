data "aws_iam_policy_document" "lambda_policy" {
  statement {
    sid = "AllowUserManagement"
    actions = [
      "iam:GetAccessKeyLastUsed",
      "iam:UpdateAccessKey",
      "iam:DeleteLoginProfile",
      "iam:ListUserTags",
      "iam:ListAccessKeys"
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
  }

  statement {
    sid = "AllowGetUserMetadata"
    actions = [
      "iam:GenerateCredentialReport",
      "iam:ListUsers",
      "iam:GetCredentialReport"
    ]
    resources = ["*"]
  }

  statement {
    sid = "AllowSendEmail"
    actions = [
      "ses:SendEmail"
    ]
    resources = [aws_ses_email_identity.email_sender.arn]
  }
}

resource "aws_iam_policy" "lambda_policy" {
  name = "iam-cleanup-lambda-policy"
  description = "Permissions for the IAM cleanup lambda function"
  path = "/"
  policy = data.aws_iam_policy_document.lambda_policy.json
}

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam-alerting-lambda-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

data "aws_iam_policy_document" "lambda_logging" {
  statement {
    sid = "AllowLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_policy" "lambda_logging" {
  name = "lambda-logging-policy"
  path = "/"
  description = "IAM policy for logging from a lambda"
  policy = data.aws_iam_policy_document.lambda_logging.json
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}