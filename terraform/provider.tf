provider "aws" {
  region = "us-west-2"
  version = "3.9.0"
}

terraform {
  backend "s3" {
    bucket = "sa-dev-tf-state"
    key    = "iam-alert-cleanup.tfstate"
    region = "us-west-2"
  }
}