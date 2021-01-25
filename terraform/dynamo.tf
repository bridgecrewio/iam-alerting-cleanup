resource "aws_dynamodb_table" "dynamo_state_table" {
  name = "iam_alerting_state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "username"
  attribute {
    name = "username"
    type = "S"
  }

  tags = {
    owner = "security"  # TODO
  }
}