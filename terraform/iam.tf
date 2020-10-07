data "aws_iam_policy_document" "lambda_policy" {
  statement {
    sid = "AllowS3"
    actions = [
      "s3:*"]
    resources = [
      "arn:aws:s3:::*"
    ]
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