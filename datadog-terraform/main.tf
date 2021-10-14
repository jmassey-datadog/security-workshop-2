variable "DD_API_KEY" {
  type = string
}

variable "DD_APP_KEY" {
  type = string
}

terraform {
  required_providers {
    datadog = {
      source = "DataDog/datadog"
    }
  }
}

# Configure the Datadog provider
provider "datadog" {
  api_key = "${var.DD_API_KEY}"
  app_key = "${var.DD_APP_KEY}"
}

resource "datadog_security_monitoring_rule" "large_number_of_unique_aws_api_calls_from_an_ec2_instance" {
  name = "Large number of unique AWS API calls from an EC2 instance"

  message = <<EOT
### Goal
Detect when an EC2 instance is compromised.

### Strategy
This rule lets you monitor CloudTrail API calls to detect when a high number (`>10`) of unique API calls are made.

### Triage and response
1. Determine if the EC2 instance **{{@userIdentity.session_name}}** is compromised.
EOT

  enabled = true


  query {
    name            = "unique_api_calls_by_instance"
    query           = "source:cloudtrail @userIdentity.session_name:i-*"
    aggregation     = "cardinality"
    group_by_fields = ["@userIdentity.session_name"]
    distinct_fields = ["@evt.name"]
  }

  case {
    status        = "high"
    condition     = "unique_api_calls_by_instance > 10"
    notifications = []
  }

  options {
    evaluation_window   = 1800
    keep_alive          = 1800
    max_signal_duration = 1800
  }

  tags = ["source:cloudtrail"]

}

resource "datadog_security_monitoring_rule" "new_account" {
  name = "New AWS Account Seen Assuming a Role into AWS Account (workshop)"

  message = <<EOT
### Goal
Detect when an attacker accesses your AWS account from their AWS Account.

### Strategy
This rule lets you monitor AssumeRole (`@evt.name:AssumeRole`) CloudTrail API calls to detect when an external AWS account (`@usr.account_id`) assumes a role into your AWS account (`account`). It does this by learning all AWS accounts from which the AssumeRole call occurs within a 7-day window. Newly detected accounts after this 7-day window will generate security signals.

### Triage and response
1. Determine if the `@usr.account_id` is an AWS account is managed by your company.
2. If not, try to determine who is the owner of the AWS account. Sometimes, you can Google the account ID and it will match a 3rd party documentation.
3. Inspect the role the account is assuming and determine who created this role and granted this AWS account to assume this role.
EOT

  enabled = true

  query {
    query           = "source:cloudtrail @evt.name:AssumeRole"
    distinct_fields = []
    aggregation     = "new_value"
    group_by_fields = ["account"]
    metric          = "@usr.account_id"
  }

  case {
    status        = "high"
    notifications = []
  }

  options {
    detection_method = "new_value"
    new_value_options {
        forget_after      = 28
        learning_duration = 0
    }
    keep_alive          = 0
    max_signal_duration = 0
    evaluation_window   = 0
  }

  tags = ["technique:T1199-trusted-relationship", "source:cloudtrail", "security:attack", "tactic:TA0001-initial-access"]
}

resource "datadog_security_monitoring_rule" "anonymous_get_object" {
  name = "Object downloaded from an S3 Bucket without authentication"

  message = <<EOT
### Goal
Detect when an object is downloaded from an S3 bucket without authentication.

### Strategy
This rule lets you monitor S3 access logs for objects downloaded (`@evt.name:GetObject`) from your S3 bucke without authentication (`@userIdentity.accountId:ANONYMOUS_PRINCIPAL`).

### Triage and response
1. Determine if the S3 bucket **{{@requestParameters.bucketName}}** and the objects downloaded should be publicly available.
EOT

  enabled = true

  query {
    name            = "unauthenticated_get_object"
    query           = "@evt.name:GetObject @userIdentity.accountId:ANONYMOUS_PRINCIPAL"
    distinct_fields = []
    aggregation     = "count"
    group_by_fields = ["@requestParameters.bucketName"]
  }

  case {
    status        = "high"
    condition     = "unauthenticated_get_object > 0"
    notifications = []
  }

  options {
    detection_method = "threshold"
    keep_alive          = 21600
    max_signal_duration = 86400
    evaluation_window   = 60
  }

  tags = ["source:cloudtrail"]
}