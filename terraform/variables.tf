variable "email_display_name" {
  description = "The email sender display name"
  type = string
}

variable "email_address" {
  description = "The email from address"
  type = string
}

locals {
  ses_email_sender = "${var.email_display_name} <${var.email_address}>"
}