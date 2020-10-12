resource "aws_ses_email_identity" "email_sender" {
  email = var.email_address
}