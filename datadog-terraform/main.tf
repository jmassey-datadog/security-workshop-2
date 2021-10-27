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

resource "datadog_dashboard" "ordered_dashboard" {
  template_variable {
    default = "*"
    prefix = "account"
    name = "AWSAccount"
  }
  template_variable {
    default = "*"
    prefix = "@usr.name"
    name = "UserName"
  }
  template_variable {
    default = "*"
    prefix = "@usr.account_id"
    name = "UserAccountID"
  }
  template_variable {
    default = "*"
    prefix = "@userIdentity.assumed_role"
    name = "AssumedRole"
  }
  template_variable {
    default = "*"
    prefix = "@evt.name"
    name = "EventName"
  }
  template_variable {
    default = "*"
    prefix = "@userIdentity.session_name"
    name = "SessionName"
  }
  template_variable {
    default = "*"
    prefix = "@network.client.ip"
    name = "ClientIP"
  }
  template_variable {
    default = "*"
    prefix = "@usr.access_key_id"
    name = "AccessKeyID"
  }
  template_variable {
    default = "*"
    prefix = "@userIdentity.type"
    name = "IdentityType"
  }
  template_variable {
    default = "*"
    prefix = "@awsRegion"
    name = "AWSRegion"
  }
  template_variable {
    default = "*"
    prefix = "@eventCategory"
    name = "EventCategory"
  }
  template_variable {
    default = "*"
    prefix = "@resource.accountId"
    name = "ResourceAccount"
  }
  template_variable {
    default = "*"
    prefix = "@resource.type"
    name = "ResourceType"
  }
  template_variable {
    default = "*"
    prefix = "@resource.ARN"
    name = "ResourceARN"
  }
  template_variable {
    default = "*"
    prefix = "@error.kind"
    name = "ErrorKind"
  }
  template_variable {
    default = "*"
    prefix = "@eventSource"
    name = "AWSService"
  }
  is_read_only = false
  title = "AWS CloudTrail"
  reflow_type = "fixed"
  widget {
    group_definition {
      title = "About AWS CloudTrail"
      # # title_align = "center"
      widget {
        image_definition {
          url = "https://datadog-docs.imgix.net/images/integrations_logos/amazon_cloudtrail.png"
          sizing = "fit"
        }
        widget_layout {
          y = 0
          x = 0
          height = 2
          width = 6
        }
      }
      widget {
        note_definition {
          tick_pos = "50%"
          font_size = "14"
          tick_edge = "left"
          text_align = "left"
          content = "AWS CloudTrail records each instance of activity detected in your environment as an event. There are 3 kinds of Cloudtrail events.- [Management events][4] -  management and network (control plane) operations performed on the resources in your AWS account,- [Data events][3] - enabled separately, data request operations such as Get, Delete, and Put API commands performed on an AWS data plane resource.- [Insight events][5] -  enabled separately, entries that reflect unusual API activity in your AWS account*For more information on Cloudtrail, please visit their [documentation][1] or our [blog post][2].*[1]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html[2]: https://www.datadoghq.com/blog/monitoring-cloudtrail-logs/[3]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html#logging-data-events[4]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#logging-management-events[5]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-insights-events-with-cloudtrail.html#insights-events-understanding"
          show_tick = false
          background_color = "transparent"
        }
        widget_layout {
          y = 2
          x = 0
          height = 5
          width = 3
        }
      }
      widget {
        note_definition {
          tick_pos = "50%"
          font_size = "14"
          tick_edge = "left"
          text_align = "left"
          content = "### Using this dashboardInvestigate anomalous activity and scope the dashboard by clicking on the entity and setting the template variables to find other correlated events. For example you might want to look for events in which a user attempted to create or change the permissions of a security group. You can click on the user entity to set the template variable for the user and see only activity for that user.You can also jump into logs or security signals explorer from the widgets. To do so, you would click on the entities to view related logs/signals which will filter your logs to look for specific activity like CreateSecurityGroup, AuthorizeSecurityGroupIngress, or AuthorizeSecurityGroupEgress events."
          show_tick = false
          background_color = "transparent"
        }
        widget_layout {
          y = 2
          x = 3
          height = 5
          width = 3
        }
      }
      layout_type = "ordered"
      background_color = "white"
    }
    widget_layout {
      y = 0
      x = 0
      height = 8
      width = 6
    }
  }
  widget {
    group_definition {
      title = "Overview"
      # # title_align = "center"
      widget {
        timeseries_definition {
          title_size = "16"
          legend_columns = ["avg","max","value"]
          yaxis {
            include_zero = true
            max = "auto"
            scale = "linear"
            min = "auto"
          }
          # # title_align = "left"
          legend_layout = "horizontal"
          show_legend = true
          title = "Cloudtrail Log Volume by AWS Account"
          request {
            formula {
              formula_expression = "query2"
            }
            style {
              line_width = "normal"
              palette = "dog_classic"
              line_type = "solid"
            }
            on_right_yaxis = false
            display_type = "bars"
            query {
              event_query {
                search {
                  query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
                }
                data_source = "logs"
                compute {
                  aggregation = "count"
                }
                name = "query2"
                indexes = ["*"]
                group_by {
                  facet = "account"
                  sort {
                    aggregation = "count"
                    order = "desc"
                  }
                  limit = 10
                }
              }
            }
          }
        }
        widget_layout {
          y = 0
          x = 0
          height = 4
          width = 6
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "account"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "AWS Accounts"
        }
        widget_layout {
          y = 4
          x = 0
          height = 3
          width = 2
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@awsRegion"
                sort_query {
                  aggregation = "count"
                  order = "desc"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "AWS Regions"
        }
        widget_layout {
          y = 4
          x = 2
          height = 3
          width = 2
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@awsRegion"
                sort_query {
                  order = "asc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Least used AWS Regions"
        }
        widget_layout {
          y = 4
          x = 4
          height = 3
          width = 2
        }
      }
      layout_type = "ordered"
      background_color = "white"
    }
    widget_layout {
      y = 0
      x = 6
      height = 8
      width = 6
    }
  }
  widget {
    group_definition {
      title = "Datadog Security Monitoring"
      # # title_align = "center"
      widget {
        note_definition {
          tick_pos = "50%"
          font_size = "14"
          tick_edge = "left"
          text_align = "left"
          content = "Datadog Security Monitoring analyzes and correlates Cloudtrail logs to detect threats to your environment in real time. If you don't see signals please make sure you're signed up for [Datadog Security Monitoring](https://app.datadoghq.com/security). "
          show_tick = false
          background_color = "pink"
        }
        widget_layout {
          y = 0
          x = 0
          height = 1
          width = 12
        }
      }
      widget {
        query_value_definition {
          custom_link {
            link = "/security?query=source:cloudtrail status:critical"
            label = "View related Security Signals"
          }
          autoscale = true
          title = "CRITICALs"
          # # title_align = "left"
          precision = 2
          title_size = "16"
          request {
            aggregator = "avg"
            conditional_formats {
              custom_bg_color = "#bc303c"
              palette = "custom_bg"
              value = 0
              comparator = ">"
            }
            security_query {
              index = "*"
              search_query = "status:critical source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 1
          x = 0
          height = 2
          width = 2
        }
      }
      widget {
        query_value_definition {
          custom_link {
            link = "/security?query=source:cloudtrail status:high"
            label = "View related Security Signals"
          }
          autoscale = true
          title = "HIGHs"
          # # title_align = "left"
          precision = 2
          title_size = "16"
          request {
            aggregator = "avg"
            conditional_formats {
              custom_bg_color = "#d33043"
              palette = "custom_bg"
              value = 0
              comparator = ">"
            }
            security_query {
              index = "*"
              search_query = "status:high source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 1
          x = 2
          height = 2
          width = 2
        }
      }
      widget {
        toplist_definition {
          request {
            conditional_formats {
              palette = "white_on_red"
              value = 0
              comparator = ">"
            }
            security_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@workflow.rule.name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          custom_link {
            link = "/security?query=@workflow.rule.name:{{@workflow.rule.name.value}}"
            label = "View related Security Signals"
          }
          title = "Security Signals"
        }
        widget_layout {
          y = 1
          x = 4
          height = 4
          width = 4
        }
      }
      widget {
        toplist_definition {
          request {
            conditional_formats {
              palette = "white_on_red"
              value = 0
              comparator = ">"
            }
            security_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@evt.name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          custom_link {
            link = "/security?query=@workflow.rule.name:{{@workflow.rule.name.value}}"
            label = "View related Security Signals"
          }
          title = "Security Signals by Events"
        }
        widget_layout {
          y = 1
          x = 8
          height = 4
          width = 4
        }
      }
      widget {
        query_value_definition {
          custom_link {
            link = "/security?source:cloudtrail status:medium"
            label = "View related Security Signals"
          }
          autoscale = true
          title = "MEDIUMs"
          # # title_align = "left"
          precision = 2
          title_size = "16"
          request {
            aggregator = "avg"
            conditional_formats {
              custom_bg_color = "#e5a21c"
              palette = "custom_bg"
              value = 0
              comparator = ">"
            }
            security_query {
              index = "*"
              search_query = "status:medium source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 3
          x = 0
          height = 2
          width = 2
        }
      }
      widget {
        query_value_definition {
          custom_link {
            link = "/security?query=source:cloudtrail status:low"
            label = "View related Security Signals"
          }
          autoscale = true
          title = "LOWs"
          # # title_align = "left"
          precision = 2
          title_size = "16"
          request {
            aggregator = "avg"
            conditional_formats {
              custom_bg_color = "#ffb52b"
              palette = "custom_bg"
              value = 0
              comparator = ">"
            }
            security_query {
              index = "*"
              search_query = "source:cloudtrail status:low $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 3
          x = 2
          height = 1
          width = 2
        }
      }
      widget {
        query_value_definition {
          custom_link {
            link = "/security?query=source:cloudtrail status:info"
            label = "View related Security Signals"
          }
          autoscale = true
          title = "INFOs"
          # # title_align = "left"
          precision = 2
          title_size = "16"
          request {
            aggregator = "avg"
            conditional_formats {
              custom_bg_color = "#84c1e0"
              palette = "custom_bg"
              value = 0
              comparator = ">"
            }
            security_query {
              index = "*"
              search_query = "status:info source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 4
          x = 2
          height = 1
          width = 2
        }
      }
      layout_type = "ordered"
      background_color = "vivid_pink"
    }
    widget_layout {
      y = 8
      x = 0
      height = 6
      width = 12
    }
  }
  widget {
    group_definition {
      title = "Resources"
      # # title_align = "center"
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@resource.accountId"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 100
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Account ID - Resource "
        }
        widget_layout {
          y = 0
          x = 0
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@resource.type"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 100
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Type - Resource"
        }
        widget_layout {
          y = 0
          x = 3
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@resource.ARN"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 100
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "ARN - Resource"
        }
        widget_layout {
          y = 0
          x = 6
          height = 3
          width = 3
        }
      }
      widget {
        note_definition {
          tick_pos = "50%"
          font_size = "12"
          tick_edge = "left"
          text_align = "left"
          content = "Resources are accessed in the event - contains the following information:* Resource ARNs* Account ID of the resource owner* Resource type identifier in the format: `AWS::aws-service-name::data-type-name`For example, when an `AssumeRole` event is logged, the resources field can appear like the following:* ARN: `arn:aws:iam::123456789012:role/myRole`* Account ID: `123456789012`* Resource type identifier: `AWS::IAM::Role`"
          show_tick = false
          background_color = "transparent"
        }
        widget_layout {
          y = 0
          x = 9
          height = 3
          width = 3
        }
      }
      layout_type = "ordered"
      background_color = "gray"
    }
    widget_layout {
      y = 14
      x = 0
      height = 4
      width = 12
    }
  }
  widget {
    group_definition {
      title = "AWS Identities"
      # # title_align = "center"
      widget {
        note_definition {
          tick_pos = "50%"
          font_size = "12"
          tick_edge = "left"
          text_align = "left"
          content = "Types of users * **Root**: The request was made with your primary AWS account credentials. If you set up an alias for your AWS account, that alias will appear here instead.* **IAMUser**: The request was made with the credentials of an IAM user.* **FederatedUser**: The request was made by a user with temporary security credentials provided through a federation token.* **AWSAccount**: The request was made by a third-party AWS account.* **AWSService**: The request was made by an AWS service account. Many AWS services use service accounts to perform automated actions on your behalf.* **AssumedRole**: The request was made with temporary credentials obtained by using the AWS Security Token Service (STS) AssumeRole operation."
          show_tick = false
          background_color = "transparent"
        }
        widget_layout {
          y = 0
          x = 0
          height = 2
          width = 12
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail @userIdentity.type:Root $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@usr.name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "AWS Root Account Activity"
        }
        widget_layout {
          y = 2
          x = 0
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          title_size = "16"
          title = "AWS Identity Types"
          # # title_align = "left"
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@userIdentity.type"
                sort_query {
                  aggregation = "count"
                  order = "desc"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 2
          x = 3
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          title_size = "16"
          title = "AWS Account IDs"
          # # title_align = "left"
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail @userIdentity.type:AWSAccount $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@usr.account_id"
                sort_query {
                  aggregation = "count"
                  order = "desc"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 2
          x = 6
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail @userIdentity.type:(IAMUser OR FederatedUser OR SAMLUser) $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@usr.name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "AWS IAM Users"
        }
        widget_layout {
          y = 2
          x = 9
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail @userIdentity.type:AssumedRole $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@userIdentity.assumed_role"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "AWS Assumed Roles"
        }
        widget_layout {
          y = 5
          x = 0
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail @userIdentity.type:AssumedRole $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@userIdentity.session_name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "AWS Session Name"
        }
        widget_layout {
          y = 5
          x = 3
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            conditional_formats {
              palette = "white_on_green"
              value = 0
              comparator = ">"
            }
            log_query {
              index = "*"
              search_query = "@evt.name:ConsoleLogin @userIdentity.type:IAMUser -status:Error $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@userIdentity.session_name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Users Logging in to Console"
        }
        widget_layout {
          y = 5
          x = 6
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          title_size = "16"
          title = "accounts with users logging into console"
          # # title_align = "left"
          request {
            log_query {
              index = "*"
              search_query = "@evt.name:ConsoleLogin @userIdentity.type:IAMUser -status:Error $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "account"
                sort_query {
                  aggregation = "count"
                  order = "desc"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 5
          x = 9
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "@evt.name:ConsoleLogin @userIdentity.type:IAMUser -status:Error $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@network.client.ip"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "IPs logging into console"
        }
        widget_layout {
          y = 8
          x = 0
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "cloudtrail"
              search_query = "@evt.name:ConsoleLogin @userIdentity.type:IAMUser -@level:Error @additionalEventData.MFAUsed:No $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@userIdentity.session_name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Users Logging in to console without MFA"
        }
        widget_layout {
          y = 8
          x = 3
          height = 3
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail @userIdentity.type:AWSService $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@userIdentity.invokedBy"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Invoking AWS Services "
        }
        widget_layout {
          y = 8
          x = 6
          height = 3
          width = 3
        }
      }
      widget {
        geomap_definition {
          style {
            palette = "hostmap_blues"
            palette_flip = false
          }
          view {
            focus = "WORLD"
          }
          title_size = "16"
          title = "Countries logging into console"
          # title_align = "left"
          request {
            log_query {
              index = "*"
              search_query = "@evt.name:ConsoleLogin @userIdentity.type:IAMUser -status:Error $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@network.client.geoip.country.iso_code"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 250
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 8
          x = 9
          height = 3
          width = 3
        }
      }
      layout_type = "ordered"
      background_color = "gray"
    }
    widget_layout {
      y = 18
      x = 0
      height = 12
      width = 12
    }
  }
  widget {
    group_definition {
      title = "Events"
      # title_align = "center"
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@evt.name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Most Frequent Events"
        }
        widget_layout {
          y = 0
          x = 0
          height = 4
          width = 2
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@evt.name"
                sort_query {
                  order = "asc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Least Frequent Events"
        }
        widget_layout {
          y = 0
          x = 2
          height = 4
          width = 2
        }
      }
      widget {
        toplist_definition {
          title_size = "16"
          title = "State Changing Events"
          # # title_align = "left"
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail @readOnly:false $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@evt.name"
                sort_query {
                  aggregation = "count"
                  order = "desc"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 0
          x = 4
          height = 4
          width = 2
        }
      }
      widget {
        query_table_definition {
          request {
            cell_display_mode = ["bar"]
            log_query {
              index = "cloudtrail"
              search_query = "-status:error $AWSService $ErrorKind $ResourceARN $ResourceType $ResourceAccount $EventCategory $AWSRegion $IdentityType $AccessKeyID $ClientIP $SessionName $EventName $AssumedRole $UserAccountID $UserName $AWSAccount"
              group_by {
                facet = "@eventSource"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              group_by {
                facet = "@evt.name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                interval = 30000
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Top events by AWS Service"
        }
        widget_layout {
          y = 0
          x = 6
          height = 4
          width = 6
        }
      }
      widget {
        note_definition {
          tick_pos = "50%"
          font_size = "12"
          tick_edge = "left"
          text_align = "left"
          content = "The requested action, which is one of the actions in the API for that service. Tracking and investigating specific events is a good way to spot anomalous activity.Example: If an attacker gets access to an EC2 instance, the first thing they might do is enumerate all of the S3 buckets that they have access to from the relevant instance profile, or attempt to change a bucket’s access policy altogether. As most automated resources already have direct access to all of the buckets they need, a `ListBuckets` or `PutBucketPolicy` call is usually worthy of investigation."
          show_tick = false
          background_color = "transparent"
        }
        widget_layout {
          y = 4
          x = 0
          height = 1
          width = 12
        }
      }
      layout_type = "ordered"
      background_color = "vivid_blue"
    }
    widget_layout {
      y = 30
      x = 0
      is_column_break = true
      height = 6
      width = 12
    }
  }
  widget {
    group_definition {
      title = "Errors"
      # # title_align = "center"
      widget {
        toplist_definition {
          request {
            conditional_formats {
              palette = "white_on_yellow"
              value = 0
              comparator = ">"
            }
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@error.kind"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Top Errors"
        }
        widget_layout {
          y = 0
          x = 0
          height = 3
          width = 3
        }
      }
      widget {
        timeseries_definition {
          title_size = "16"
          legend_columns = ["avg","max","value","sum"]
          yaxis {
            include_zero = true
            max = "auto"
            scale = "linear"
            min = "auto"
          }
          # # title_align = "left"
          legend_layout = "vertical"
          show_legend = true
          title = "Top Errors"
          request {
            formula {
              formula_expression = "query1"
            }
            style {
              line_width = "normal"
              palette = "orange"
              line_type = "solid"
            }
            on_right_yaxis = false
            display_type = "bars"
            query {
              event_query {
                search {
                  query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
                }
                data_source = "logs"
                compute {
                  aggregation = "count"
                }
                name = "query1"
                indexes = ["*"]
                group_by {
                  facet = "@error.kind"
                  sort {
                    aggregation = "count"
                    order = "desc"
                  }
                  limit = 25
                }
              }
            }
          }
        }
        widget_layout {
          y = 0
          x = 3
          height = 3
          width = 6
        }
      }
      widget {
        toplist_definition {
          request {
            conditional_formats {
              palette = "white_on_yellow"
              value = 0
              comparator = ">"
            }
            log_query {
              index = "*"
              search_query = "source:cloudtrail @error.kind:AccessDenied $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@evt.name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Events with Access Denied"
        }
        widget_layout {
          y = 0
          x = 9
          height = 3
          width = 3
        }
      }
      widget {
        query_table_definition {
          request {
            conditional_formats {
              palette = "white_on_yellow"
              value = 0
              comparator = ">"
            }
            conditional_formats {
              metric = "count:*"
              palette = "yellow_on_white"
              value = 0
              comparator = ">"
            }
            conditional_formats {
              metric = "cardinality:@evt.name"
              palette = "yellow_on_white"
              value = 0
              comparator = ">"
            }
            cell_display_mode = ["bar","bar"]
            log_query {
              index = "*"
              search_query = "source:cloudtrail @userIdentity.session_name:i-* @error.kind:AccessDenied"
              group_by {
                facet = "@userIdentity.session_name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              multi_compute {
                aggregation = "count"
              }
              multi_compute {
                facet = "@evt.name"
                aggregation = "cardinality"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Instances with Access Denied"
        }
        widget_layout {
          y = 3
          x = 0
          height = 3
          width = 4
        }
      }
      widget {
        query_table_definition {
          request {
            conditional_formats {
              palette = "white_on_yellow"
              value = 0
              comparator = ">"
            }
            conditional_formats {
              metric = "count:*"
              palette = "yellow_on_white"
              value = 0
              comparator = ">"
            }
            conditional_formats {
              metric = "cardinality:@evt.name"
              palette = "yellow_on_white"
              value = 0
              comparator = ">"
            }
            cell_display_mode = ["bar","bar"]
            log_query {
              index = "*"
              search_query = "source:cloudtrail @error.kind:AccessDenied @evt.name:* $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@network.client.ip"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              multi_compute {
                aggregation = "count"
              }
              multi_compute {
                facet = "@evt.name"
                aggregation = "cardinality"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "IPs with Access Denied"
        }
        widget_layout {
          y = 3
          x = 4
          height = 3
          width = 4
        }
      }
      widget {
        query_table_definition {
          request {
            conditional_formats {
              palette = "white_on_yellow"
              value = 0
              comparator = ">"
            }
            conditional_formats {
              metric = "cardinality:@evt.name"
              palette = "yellow_on_white"
              value = 0
              comparator = ">"
            }
            conditional_formats {
              metric = "count:*"
              palette = "yellow_on_white"
              value = 0
              comparator = ">"
            }
            cell_display_mode = ["bar","bar"]
            log_query {
              index = "*"
              search_query = "source:cloudtrail @error.kind:AccessDenied"
              group_by {
                facet = "@userIdentity.session_name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              multi_compute {
                aggregation = "count"
              }
              multi_compute {
                facet = "@evt.name"
                aggregation = "cardinality"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Sessions with Access Denied"
        }
        widget_layout {
          y = 3
          x = 8
          height = 3
          width = 4
        }
      }
      widget {
        note_definition {
          tick_pos = "50%"
          font_size = "12"
          tick_edge = "left"
          text_align = "left"
          content = "The AWS service error if the request returns an error.Anomalous errors can be worth investigations. For exampleunauthorized user activity logs contain the following error message in the response `Client.UnauthorizedOperation`A single unauthorized activity log is not necessarily indicative of a threat. For instance, the unauthorized action may have occurred due to a user not having the permissions needed to view certain AWS console resources. Or it could be the result of a service attempting to call on a resource for which it does not have access.However, if this is the first time an IAM user is receiving an authorization error, it might be worth investigating what caused the error."
          show_tick = false
          background_color = "transparent"
        }
        widget_layout {
          y = 6
          x = 0
          height = 2
          width = 12
        }
      }
      layout_type = "ordered"
      background_color = "vivid_orange"
    }
    widget_layout {
      y = 36
      x = 0
      height = 9
      width = 12
    }
  }
  widget {
    group_definition {
      title = "S3 Data Events"
      # # title_align = "center"
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "@requestParameters.bucketName:* @eventCategory:Data $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@userIdentity.session_name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Top sessions making requests to buckets"
        }
        widget_layout {
          y = 0
          x = 0
          height = 4
          width = 3
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "@requestParameters.bucketName:* @eventCategory:Data $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@evt.name"
                sort_query {
                  order = "desc"
                  aggregation = "count"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Data Events"
        }
        widget_layout {
          y = 0
          x = 3
          height = 4
          width = 3
        }
      }
      widget {
        timeseries_definition {
          title_size = "16"
          title = "Requests to Buckets"
          # # title_align = "left"
          yaxis {
            include_zero = true
            max = "auto"
            scale = "linear"
            min = "auto"
          }
          show_legend = false
          request {
            style {
              line_width = "normal"
              palette = "dog_classic"
              line_type = "solid"
            }
            display_type = "line"
            log_query {
              index = "*"
              search_query = "@eventCategory:Data $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@requestParameters.bucketName"
                sort_query {
                  aggregation = "count"
                  order = "desc"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
        }
        widget_layout {
          y = 0
          x = 6
          height = 2
          width = 6
        }
      }
      widget {
        note_definition {
          tick_pos = "50%"
          font_size = "12"
          tick_edge = "left"
          text_align = "left"
          content = "Because they are often high-volume activities, data events are disabled by default when you create a trail; you must add the resources or resource types to a trail in order to track them in AWS CloudTrail. [Learn how to enable them here][1]Data events provide details on the operations performed on or within a resource or service, such as AWS IAM roles, Amazon EC2 instances, Amazon S3 buckets, and AWS Lambda functions. For example `PutObject` on S3 buckets are logged by Cloudtrail Data Events.[1]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.htmlhttps://docs.amazonaws.cn/en_us/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html"
          show_tick = false
          background_color = "transparent"
        }
        widget_layout {
          y = 2
          x = 6
          height = 2
          width = 6
        }
      }
      layout_type = "ordered"
      background_color = "gray"
    }
    widget_layout {
      y = 45
      x = 0
      height = 5
      width = 12
    }
  }
  widget {
    group_definition {
      title = "AssumeRole Activity"
      # # title_align = "center"
      widget {
        log_stream_definition {
          sort {
            column = "time"
            order = "desc"
          }
          show_date_column = true
          title_size = "16"
          title = "AssumeRole Calls"
          # # title_align = "left"
          message_display = "inline"
          indexes = ["cloudtrail"]
          show_message_column = false
          query = "@evt.name:AssumeRole -status:error $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
          columns = ["status","@requestParameters.roleSessionName","@userIdentity.type","@userIdentity.invokedBy","@userIdentity.accountId","@usr.access_key_id"]
        }
        widget_layout {
          y = 0
          x = 0
          height = 4
          width = 8
        }
      }
      widget {
        note_definition {
          tick_pos = "50%"
          font_size = "12"
          tick_edge = "left"
          text_align = "left"
          content = "`AssumedRole` calls are request which was made with temporary credentials obtained by using the AWS Security Token Service (STS). AssumedRoles can obfuscate the name of the user who performed the action.As an example users with no IAM policies directly associated with them can assume roles into a separate account which contains IAM roles when they need to perform an action.A good way to control assumed roles and more easily track users who perform actions using assumed roles is to [stipulate the user’s session name][1]. To do this, you specify the permissible session names in the trust policy of the role that will be assumed.[1]: https://aws.amazon.com/blogs/security/easily-control-naming-individual-iam-role-sessions/"
          show_tick = false
          background_color = "transparent"
        }
        widget_layout {
          y = 0
          x = 8
          height = 3
          width = 4
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail @evt.name:AssumeRole $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@usr.account_id"
                sort_query {
                  aggregation = "count"
                  order = "desc"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Accounts Assuming Role Into AWS account"
        }
        widget_layout {
          y = 3
          x = 8
          height = 3
          width = 4
        }
      }
      widget {
        log_stream_definition {
          sort {
            column = "time"
            order = "desc"
          }
          show_date_column = true
          title_size = "16"
          title = "AssumedRole Calls"
          # # title_align = "left"
          message_display = "inline"
          indexes = ["cloudtrail"]
          show_message_column = false
          query = "@userIdentity.type:AssumedRole $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
          columns = ["status","@userIdentity.accountId","@evt.name","@userIdentity.session_name","@userIdentity.invokedBy","@usr.access_key_id"]
        }
        widget_layout {
          y = 4
          x = 0
          height = 5
          width = 8
        }
      }
      widget {
        toplist_definition {
          request {
            log_query {
              index = "*"
              search_query = "source:cloudtrail $AWSAccount $UserName $UserAccountID $AssumedRole $EventName $SessionName $ClientIP $AccessKeyID $IdentityType $AWSRegion $EventCategory $ResourceAccount $ResourceType $ResourceARN $ErrorKind $AWSService"
              group_by {
                facet = "@usr.access_key_id"
                sort_query {
                  aggregation = "count"
                  order = "desc"
                }
                limit = 10
              }
              compute_query {
                aggregation = "count"
              }
            }
          }
          # # title_align = "left"
          title_size = "16"
          title = "Access Key IDs"
        }
        widget_layout {
          y = 6
          x = 8
          height = 3
          width = 4
        }
      }
      layout_type = "ordered"
      background_color = "gray"
    }
    widget_layout {
      y = 50
      x = 0
      height = 10
      width = 12
    }
  }
  layout_type = "ordered"
}